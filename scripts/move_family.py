#!/usr/bin/env python3
"""Move one tool family into the family-owned layout of public #42 (step 5).

The one shared family-move tool (``codemod_move_wrappers.py`` only moved server.py's inline
wrappers). Run from the repository root, in the dev virtualenv::

    python scripts/move_family.py --family carrier           # move the family
    python scripts/move_family.py --family carrier --check   # dry run: what would change
    python scripts/move_family.py --report                   # every family's plan
    python scripts/move_family.py --family protect --keep-cross-family  # layout only

``--keep-cross-family`` moves the layout but leaves F's imports of other families where
they are (listed, and pinned in the family test as hand work still to do).

One command moves the whole family ``F`` (``families/F/``):

``registrar.py``
    Every ``register`` / ``register_<n>`` function of F's modules (the thin tool wrappers),
    moved verbatim in loader-map order and numbered ``register``, ``register_2``, ... Each
    keeps the imports its body names. Handlers are always called through a module alias:
    a bare call of a family module's function (``from .handlers import x`` or
    a function of the wrapper's own module) becomes ``<module>.x(...)``, so a test that
    patches ``<module>.x`` reaches the wrapper. A call through a ``sys.modules`` self-alias
    (typed ``Any``) that spreads ``*deps_fn()`` before more arguments is written as
    ``client, registry = deps_fn()`` and an explicit call, so the output type-checks
    without ignores once the call is typed.
``schemas.py``
    F's module-level constants (routes, limits, sort and field sets: an assignment built
    only from literals and earlier constants), moved with their ``#:`` comments. Each
    module imports them back, so ``<module>.<NAME>`` and a patch of it still apply to that
    module's own functions; a name the module no longer reads once its wrappers have moved
    is re-exported explicitly (``X as X``), so the unused-import cleanup keeps it. A name
    two of F's modules bind differently stays put.
``handlers.py``
    The handler index (a block between generated markers): each of F's tools and the
    ``module:function`` its wrapper calls. The implementations stay in their modules, at
    their import paths (families still import each other during the moves).
``catalog/loaders.py``
    F's entries name ``registrar`` and its new function. The order, each ``deps`` form and
    each ``origin`` (the ``MODULE_INDEX`` stem) stay, so ``tools/list`` and the discovery
    vocabulary do not change. ``gen_loaders.py --check`` proves membership, not order: the
    A1 comparator (``dump_tool_baseline.py --compare l1``) is the order guard.
    ``FAMILY_DEPENDENCIES`` is carried through unchanged and never read for a decision
    (nothing checks it).
Cross-family imports (what :func:`family_imports` lists for F)
    Each name F imports from another family ``X`` moves out of ``X`` with the definitions
    it needs (a package module outside ``families/`` that reads it counts as a user too). It
    goes to the common package (``shared_shapes/_<module>_shared.py``,
    ``loaders.COMMON_PACKAGE``) only when two or more families use it (X itself, F, or
    any other family importing it); a name only F uses becomes F's private
    ``families/F/_<module>_shared.py``. X imports a shared name back where it uses it. The
    closure follows X's own sibling imports (``from .other_module import helper``): that
    helper moves into the same target. A closure that would take a tool wrapper, an X module
    alias (``from . import m``), an aliased sibling import, another family's import or a
    ``global``-rebound name is refused: that is hand work, and the reason is printed.
Module identity
    Moved code keeps its log channel: ``getLogger(__name__)`` is written with the original
    module's dotted name. Any other read of a module attribute (``__name__``, ``__file__``,
    ...) in code that would move is refused as hand work.
Keys and calls that follow the move
    Each moved wrapper's ``families/F/<module>.py:<register>.<wrapper>`` key and each moved
    helper's ``families/X/<module>.py:<name>`` key (the refusal registry, the test
    allowlists, the ledgers) names the new file. Every ``<module>.register*`` read in
    ``tests/``, ``scripts/`` and ``docs/`` of a moved module (through any import
    alias, or ``server.<module>``) becomes ``<family>_registrar.<new name>``. What cannot be
    resolved statically (a ``register`` read on a loop variable, a bare file reference to a
    module helpers left) is printed as a ``hand check``.
``tests/test_<family>_family.py``
    The generated family layout test.
No changelog fragment: a family move is contributor-only (no user-visible change); its
pull request carries the ``skip-changelog`` label instead.

After writing, the touched files are import-sorted and formatted with ruff, unused imports
are dropped from the modules that lost code, and, where the repository has the acceptance
harness (``docs/*/write_acceptance_route_sources.py`` and ``write_acceptance_na_proofs.py``;
the public tree does not), its route citations are regenerated and its N/A proof citations
followed. The generated tool-shape table (``tests/tool_shapes_gen.py --write``), which
records each shape class's module, is regenerated. Where the tree has the explicit tool
inventory (``catalog/membership.py``), ``gen_membership.py --generate`` refreshes its steps
(the server refuses to start on a stale step) and the move fails unless every
``(tool, family)`` pair is unchanged: a move changes steps only. ``deferred.json`` is then
regenerated from it (``gen_deferred_catalog.py --generate``). The move is all or
nothing: if a write, a generator, an import of the moved tree (the server, or
every written module), ruff F821 on the written modules or one in-process tool call per
touched family (through the server's middleware) fails, every file is restored and the run
exits 1 (``ROLLED BACK``). The route citations are then checked (``--check``): a drifted
citation fails the move too. The caller's shell cannot steer any of it: the run clears
every ``UNIFI_*``/``MCP_*``/``FASTMCP_*`` variable first, and every process it starts (ruff,
the generators, the route-source writer and check, the probes) gets that scrubbed
environment, the moved tree first on its path and a placeholder key.

The script is deterministic and idempotent: a moved family is a fixed point, and
``--check`` prints what would change and exits 1 if anything would (0 when moved).
``--report`` prints each family's tool count, steps, modules, cross-family imports and
whether its move is automatic or needs hand work first.

Exit status: 0 done / nothing to do, 1 ``--check`` found changes or a move was refused,
2 a usage error.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import difflib
import importlib.util
import re
import subprocess
import sys
import textwrap
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "unifi_fabric"
FAMILIES = PKG / "families"
SHARED = PKG / "shared_shapes"
LOADERS_FILE = PKG / "catalog" / "loaders.py"
TESTS = ROOT / "tests"
#: The acceptance harness's route-source writer, where the repository has one (the public
#: tree does not): found under ``docs/``, run after a move, and skipped when absent.
ROUTE_SOURCES_NAME = "write_acceptance_route_sources.py"
ROUTE_SOURCES = next(iter(sorted(ROOT.glob(f"docs/*/{ROUTE_SOURCES_NAME}"))), None)

LAYOUT_STEMS = ("handlers", "schemas", "registrar")
#: The explicit tool inventory, the lazy-loading snapshot and their generators (absent in a
#: tree without them).
MEMBERSHIP = PKG / "catalog" / "membership.py"
MEMBERSHIP_GEN = ROOT / "scripts" / "gen_membership.py"
DEFERRED = PKG / "catalog" / "deferred.json"
DEFERRED_GEN = ROOT / "scripts" / "gen_deferred_catalog.py"
#: The generated tool-shape table and its generator (absent in a tree without them).
SHAPES_GEN = TESTS / "tool_shapes_gen.py"
SHAPES_TABLE = PKG / "generated_api_facts" / "_tool_shapes_table.py"
#: Module attributes whose value depends on the module that reads them.
_MODULE_DUNDERS = frozenset(
    {"__name__", "__file__", "__spec__", "__package__", "__loader__", "__path__", "__cached__"}
)
#: The probe's API key: a placeholder that never reaches a console.
PROBE_KEY = "move-family-probe-placeholder"
#: Ambient settings no process of a move may inherit (a family filter, a real key, a
#: transport): with ``UNIFI_FAMILY_ALLOW`` set, the route-source writer wrote emptied
#: citations and the move still passed.
_SCRUBBED = ("UNIFI_", "MCP_", "FASTMCP_")
#: The import-back header of a module's moved shapes.
_SCHEMAS_BACK = "from .schemas import (  # the family's shapes (family-owned layout)\n"
_REGISTER_RE = re.compile(r"register(?:_[0-9]+)?")
HANDLERS_BEGIN = "# --- generated by scripts/move_family.py: the handler index ---"
HANDLERS_END = "# --- end of the generated handler index ---"
#: Calls a module-level constant may contain (pure, deterministic, no state).
_PURE_CALLS = frozenset({"frozenset", "tuple", "set", "dict", "list", "len", "sorted"})


class Refused(Exception):
    """A move this codemod will not make automatically (hand work)."""


def _gen_loaders() -> Any:
    path = ROOT / "scripts" / "gen_loaders.py"
    spec = importlib.util.spec_from_file_location("gen_loaders", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("gen_loaders", module)
    spec.loader.exec_module(module)
    return module


GEN = _gen_loaders()


# --------------------------------------------------------------------------- AST helpers


def _free_names(node: ast.AST) -> list[str]:
    """Names ``node`` loads that it does not bind itself (builtins excluded), in order."""
    bound: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.arg):
            bound.add(child.arg)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            bound.add(child.id)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if child is not node:
                bound.add(child.name)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            bound.add(child.name)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(child, ast.comprehension):
            for sub in ast.walk(child.target):
                if isinstance(sub, ast.Name):
                    bound.add(sub.id)
    out: list[str] = []
    loads = sorted(
        (c for c in ast.walk(node) if isinstance(c, ast.Name) and isinstance(c.ctx, ast.Load)),
        key=lambda c: (c.lineno, c.col_offset),
    )
    for child in loads:
        if child.id not in bound and not hasattr(builtins, child.id) and child.id not in out:
            out.append(child.id)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        out = [n for n in out if n != node.name]
    return out


def _stmt_start(node: ast.stmt) -> int:
    decorators = getattr(node, "decorator_list", [])
    return min([node.lineno, *(d.lineno for d in decorators)])


def _assigned_names(node: ast.stmt) -> list[str]:
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    else:
        return []
    return [c.id for t in targets for c in ast.walk(t) if isinstance(c, ast.Name)]


def _defined(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return _assigned_names(node)
    if isinstance(node, ast.TypeAlias):
        return [node.name.id]
    return []


@dataclass(frozen=True)
class Binding:
    """How a module binds a top-level name."""

    kind: str  # "import" | "from" | "def"
    module: str = ""  # dotted (with leading dots for relative) source of an import
    name: str = ""  # the imported attribute (from-import) or module (import)

    def line(self, local: str) -> str:
        if self.kind == "import":
            return f"import {self.name}" + (
                f" as {local}" if local != self.name.split(".")[0] else ""
            )
        alias = f" as {local}" if local != self.name else ""
        return f"from {self.module} import {self.name}{alias}"


def _bindings(tree: ast.Module) -> dict[str, Binding]:
    out: dict[str, Binding] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = Binding("import", "", alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                out[alias.asname or alias.name] = Binding("from", module, alias.name)
        else:
            for name in _defined(node):
                out.setdefault(name, Binding("def"))
    return out


def _is_register(node: ast.stmt) -> bool:
    return isinstance(node, ast.FunctionDef) and bool(_REGISTER_RE.fullmatch(node.name))


def _is_tool(node: ast.AST) -> bool:
    if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
        return False
    for dec in node.decorator_list:
        func = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(func, ast.Attribute) and func.attr == "tool":
            return True  # @mcp.tool, @mcp.tool(...)
        if isinstance(func, ast.Name) and func.id == "tool":
            return True  # a bare @tool / @tool(...) (``tool = mcp.tool``)
    return False


def _tool_name(node: ast.AsyncFunctionDef | ast.FunctionDef) -> str:
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    return str(kw.value.value)
    return node.name


def _pure(node: ast.AST, constants: set[str]) -> bool:
    """A constant expression: literals, containers and earlier constants only."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_pure(e, constants) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and _pure(k, constants) for k in node.keys) and all(
            _pure(v, constants) for v in node.values
        )
    if isinstance(node, ast.JoinedStr):
        return all(_pure(v, constants) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _pure(node.value, constants) and node.format_spec is None
    if isinstance(node, ast.BinOp):
        return _pure(node.left, constants) and _pure(node.right, constants)
    if isinstance(node, ast.UnaryOp):
        return _pure(node.operand, constants)
    if isinstance(node, ast.Name):
        return node.id in constants
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return (
            node.func.id in _PURE_CALLS
            and not node.keywords
            and all(_pure(a, constants) for a in node.args)
        )
    return False


_ANNOTATION_IMPORTS = frozenset({"typing", "collections.abc", "types", "__future__"})


# --------------------------------------------------------------------------- model


@dataclass
class Source:
    """One module file of the family, its text and parse."""

    path: Path
    text: str
    tree: ast.Module = field(init=False)

    def __post_init__(self) -> None:
        self.tree = ast.parse(self.text)

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines(keepends=True)

    def segment(self, node: ast.stmt, *, comments: bool = True) -> tuple[int, int]:
        """1-based ``(first, last)`` lines of ``node``, with its leading ``#`` comments."""
        first, last = _stmt_start(node), node.end_lineno or node.lineno
        lines = self.lines
        if comments:
            while first > 1 and lines[first - 2].lstrip().startswith("#"):
                first -= 1
        return first, last


@dataclass
class Plan:
    """What a family move writes, and what it found."""

    family: str
    files: dict[Path, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    lost_code: set[Path] = field(default_factory=set)
    #: ``(old file, new file, names)`` of each helper group moved out of a module (keys).
    moved_helpers: list[tuple[str, str, set[str]]] = field(default_factory=list)
    #: ``families/<f>/<module>.py`` -> the wrapper and tool names its moved steps defined.
    moved_wrappers: dict[str, set[str]] = field(default_factory=dict)
    #: module path -> (its ``from .schemas import`` block as written, the names in it).
    schema_backs: dict[Path, tuple[str, list[str]]] = field(default_factory=dict)

    def changed(self) -> dict[Path, str]:
        return {
            p: t
            for p, t in self.files.items()
            if not p.exists() or p.read_text(encoding="utf-8") != t
        }


def _family_sources(family: str, files: dict[Path, str]) -> dict[str, Source]:
    out: dict[str, Source] = {}
    for path in sorted((FAMILIES / family).glob("*.py")):
        if path.name == "__init__.py":
            continue
        out[path.stem] = Source(path, files[path] if path in files else path.read_text("utf-8"))
    return out


def _remove_ranges(text: str, ranges: Iterable[tuple[int, int]]) -> str:
    """Drop the 1-based inclusive line ranges and the blank lines just after each."""
    lines = text.splitlines(keepends=True)
    drop: set[int] = set()
    for first, last in ranges:
        end = last
        while end < len(lines) and not lines[end].strip():
            end += 1
        drop.update(range(first - 1, end))
    kept = "".join(line for i, line in enumerate(lines) if i not in drop)
    return kept.rstrip("\n") + "\n"


def _insert_after_imports(text: str, block: str) -> str:
    """Insert ``block`` after the module's last top-level import before other code."""
    tree = ast.parse(text)
    anchor = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            anchor = node.end_lineno or node.lineno
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            anchor = anchor or (node.end_lineno or node.lineno)
        else:
            break
    lines = text.splitlines(keepends=True)
    lines.insert(anchor, block if block.endswith("\n") else block + "\n")
    return "".join(lines)


# --------------------------------------------------------------------------- loader map


def _loaders() -> tuple[list[Any], dict[str, tuple[str, ...]]]:
    sys.path.insert(0, str(PKG.parent))
    from unifi_fabric.catalog.loaders import FAMILY_DEPENDENCIES, LOADERS

    return list(LOADERS), dict(FAMILY_DEPENDENCIES)


def _numbered(index: int) -> str:
    return "register" if index == 0 else f"register_{index + 1}"


# --------------------------------------------------------------------------- the move


def _parse_family_import(node: ast.ImportFrom, dirs: set[str]) -> tuple[str, str | None] | None:
    """``(other family, module or None)`` of a module-level relative import of a family."""
    if not node.level:
        return None
    parts = (node.module or "").split(".")
    if node.level == 2:
        if not parts[0]:
            return None  # ``from .. import x``: the package, not a family
        other, rest = parts[0], parts[1:]
    elif node.level == 3 and parts[0] == "families" and len(parts) > 1:
        other, rest = parts[1], parts[2:]
    else:
        return None
    if other not in dirs:
        return None
    return other, (rest[0] if rest else None)


def _family_imports(
    importer: str, files: dict[Path, str]
) -> list[tuple[Source, ast.ImportFrom, str, str, dict[str, str], str | None]]:
    """Each import of another family by ``importer``'s modules.

    ``(source, node, other family, other module, {name: local}, module alias)``: a
    by-name import (``from ..x.m import a``) has no module alias; a module import
    (``from ..x import m``, used as ``m.attr``) lists the attributes it reads.
    """
    dirs = set(GEN.family_dirs())
    out = []
    for _stem, src in _family_sources(importer, files).items():
        for node in src.tree.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            parsed = _parse_family_import(node, dirs)
            if parsed is None or parsed[0] == importer:
                continue
            other, module = parsed
            if module is not None:
                names = {a.name: a.asname or a.name for a in node.names}
                out.append((src, node, other, module, names, None))
                continue
            for alias in node.names:
                local = alias.asname or alias.name
                attrs = sorted(
                    {
                        c.attr
                        for c in ast.walk(src.tree)
                        if isinstance(c, ast.Attribute)
                        and isinstance(c.value, ast.Name)
                        and c.value.id == local
                    }
                )
                out.append((src, node, other, alias.name, {a: a for a in attrs}, local))
    return out


def family_imports(family: str | None = None) -> list[tuple[str, int, str]]:
    """``(file, line, other family)`` of each module-level import of another family.

    The source scan this tool moves by (a relative ``from ..x[.m] import ...`` or
    ``from ...families.x[.m] import ...`` at module level). It is not the cross-family
    gate: ``scripts/check_family_imports.py`` is the one cross-family rule.
    """
    found: list[tuple[str, int, str]] = []
    for importer in [family] if family else GEN.family_dirs():
        for src, node, other, _module, _names, _alias in _family_imports(importer, {}):
            found.append((f"families/{importer}/{src.path.name}", node.lineno, other))
    return sorted(set(found))


def _cross_family(family: str, plan: Plan, files: dict[Path, str]) -> None:
    """Move F's imports of other families out of the other family (or refuse).

    A helper goes to the common package only when two or more families use
    it; a helper only F uses moves into F as a private ``_<module>_shared.py``.
    """
    found = _family_imports(family, files)
    if not found:
        return
    # Every family's reads of each other family's module (for the two-family rule).
    readers: dict[tuple[str, str], dict[str, set[str]]] = {}
    for reader in GEN.family_dirs():
        for _src, _node, other, module, names, _alias in _family_imports(reader, files):
            for name in names:
                readers.setdefault((other, module), {}).setdefault(name, set()).add(reader)
    edits: dict[Path, list[tuple[ast.ImportFrom, list[str]]]] = {}
    for src, node, other, module, names, alias in found:
        place, target = _move_shared(family, other, module, sorted(names), readers, plan, files)
        if alias is None:
            imported = ", ".join(
                n if names[n] == n else f"{n} as {names[n]}" for n in sorted(names)
            )
            dotted = f".{target}" if place == "." else f"{place}.{target}"
            lines = [f"from {dotted} import {imported}"]
        else:
            lines = [f"from {place} import {target} as {alias}  # {other}.{module}'s shared names"]
        edits.setdefault(src.path, []).append((node, lines))
        where = "shared_shapes" if place.endswith("shared_shapes") else f"families/{family}"
        plan.notes.append(
            f"cross-family: families/{family}/{src.path.name}:{node.lineno} "
            f"({other}.{module}: {', '.join(sorted(names)) or '-'}) -> {where}/{target}.py"
        )
    for path, items in edits.items():
        src = Source(path, files[path] if path in files else path.read_text("utf-8"))
        lines = src.lines
        # One import statement may name several modules: rebuild it once.
        by_node: dict[int, tuple[ast.ImportFrom, list[str]]] = {}
        for node, new in items:
            by_node.setdefault(node.lineno, (node, []))[1].extend(new)
        for lineno in sorted(by_node, reverse=True):
            node, new = by_node[lineno]
            lines[node.lineno - 1 : node.end_lineno] = [line + "\n" for line in new]
        files[path] = "".join(lines)
        plan.lost_code.add(path)


def _doc(summary: str, *paragraphs: str) -> str:
    """A module docstring wrapped at 100 columns (ruff E501): summary, then paragraphs."""
    wrap = {"width": 100, "break_long_words": False, "break_on_hyphens": False}
    lines = textwrap.wrap(summary, initial_indent='"""', **wrap)
    for paragraph in paragraphs:
        lines += ["", *textwrap.wrap(paragraph, **wrap)]
    return "\n".join(lines) + '\n"""\n'


def _move_shared(
    family: str,
    other: str,
    module: str,
    names: Sequence[str],
    readers: dict[tuple[str, str], dict[str, set[str]]],
    plan: Plan,
    files: dict[Path, str],
) -> tuple[str, str]:
    """Move ``names`` (and what they need) out of the ``other`` family.

    Returns ``(package, module)`` to import them from: ``...shared_shapes`` and
    ``_<module>_shared`` when two or more families use them, else ``.`` and F's private
    ``_<module>_shared``. A name already moved by an earlier family's run is reused.

    The closure follows the other family's own sibling imports (``from .x import y`` in
    ``other``): ``y`` moves out of ``x`` too, into the same target, so a helper that
    reaches a sibling module's helper is not hand work.
    """
    target = f"_{module}_shared"  # module stems are unique across families (module keys)
    common_path = SHARED / f"{target}.py"
    local_path = FAMILIES / family / f"{target}.py"
    sources = _family_sources(other, files)
    if module not in sources:
        raise Refused(f"{other} has no module {module!r}")

    def existing(path: Path) -> Source | None:
        if path in files:
            return Source(path, files[path])
        return Source(path, path.read_text(encoding="utf-8")) if path.exists() else None

    def targets_target(binding: Binding) -> bool:
        # An import of the target itself (an earlier group of this run, or an earlier
        # run, already moved that name there): never carried into the target (no cycle).
        return binding.kind == "from" and binding.module.lstrip(".").split(".")[-1] == target

    binds = {stem: _bindings(src.tree) for stem, src in sources.items()}
    # Already moved by an earlier run (or an earlier family's PR): only repoint.
    for path, package in ((common_path, "...shared_shapes"), (local_path, ".")):
        have = existing(path)
        if have is not None and all(n in _bindings(have.tree) for n in names):
            if all(binds[module].get(n, Binding("def")).kind != "def" for n in names):
                return package, target
    rebound = {
        stem: {n for c in ast.walk(src.tree) if isinstance(c, ast.Global) for n in c.names}
        for stem, src in sources.items()
    }
    dirs = set(GEN.family_dirs())
    # (stem, node id) -> node; the order is dependencies first (post-order).
    closure: dict[tuple[str, int], ast.stmt] = {}
    order: list[tuple[str, ast.stmt]] = []
    needed_imports: dict[str, Binding] = {}
    visiting: set[tuple[str, str]] = set()

    def visit(stem: str, name: str) -> None:
        if (stem, name) in visiting:
            return
        visiting.add((stem, name))
        binding = binds[stem].get(name)
        where = f"{other}/{stem}.py:{name}"
        if binding is None:
            raise Refused(f"{other}/{stem}.py has no top-level {name!r}")
        if binding.kind != "def":
            mod = binding.module
            if targets_target(binding):
                # Already in a module of the target's name; whether that is the file this
                # move writes is known only once the destination is (see import_lines).
                needed_imports.setdefault(name, binding)
                return
            if binding.kind == "from" and mod == ".":
                raise Refused(f"{where} is an {other} module alias ({binding.line(name)})")
            if binding.kind == "from" and mod.startswith(".") and not mod.startswith(".."):
                sibling = mod[1:]
                if sibling not in sources or binding.name != name:
                    raise Refused(f"{where} is an {other}-local import ({binding.line(name)})")
                visit(sibling, name)  # follow the sibling's own definition
                return
            if binding.kind == "from" and mod.startswith("..") and not mod.startswith("..."):
                if mod[2:].split(".")[0] in dirs:
                    raise Refused(f"{where} comes from another family ({binding.line(name)})")
            if needed_imports.setdefault(name, binding) != binding:
                raise Refused(f"{where}: {name!r} is imported two ways in {other}")
            return
        group = [n for n in sources[stem].tree.body if name in _defined(n)]
        if len(group) > 1 and not all(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in group
        ):
            # ``X = ...`` and ``def X`` (or two assignments): which binding a reader saw
            # depends on import-time order; moving one would change it.
            raise Refused(f"{where} is bound more than once at module level")
        # One definition, or an ``@overload`` group (stubs and implementation): all move
        # together, in source order, so the last one is still the name's binding.
        if any(_is_register(n) or _is_tool(n) for n in group):
            raise Refused(f"{where} registers tools")
        if name in rebound[stem]:
            raise Refused(f"{where} is rebound with `global`")
        if (stem, id(group[0])) in closure:
            return
        for node in group:
            closure[(stem, id(node))] = node
        for node in group:
            for free in _free_names(node):
                visit(stem, free)
        order.extend((stem, node) for node in group)

    for name in names:
        visit(module, name)
    if not order:
        raise Refused(f"{other}/{module}.py: {', '.join(names)} are themselves imports")
    moved_by_stem: dict[str, list[str]] = {}
    for stem, node in order:
        moved_by_stem.setdefault(stem, []).extend(_defined(node))
    moved_names = sorted({n for ns in moved_by_stem.values() for n in ns})
    users = {family}
    for stem, stem_names in moved_by_stem.items():
        for name in stem_names:
            users |= readers.get((other, stem), {}).get(name, set())
    if _family_uses(moved_by_stem, set(closure), sources):
        users.add(other)
    core = _core_reads(files)
    if any(n in core.get((other, stem), set()) for stem, ns in moved_by_stem.items() for n in ns):
        users.add("core")  # a module outside families/ reads it from its family module
    shared = len(users) >= 2
    path = common_path if shared else local_path
    package = "...shared_shapes" if shared else "."
    # Never an import of the file being written (no self-import), but an import of a
    # same-named module elsewhere (the common package, for a family-private target) stays.
    own = f"...shared_shapes.{target}" if shared else f".{target}"
    import_lines = sorted(
        {
            _relevel(b.line(n), 3, 2 if shared else 3)
            for n, b in needed_imports.items()
            if not (b.kind == "from" and b.module == own)
        }
    )
    body = "\n\n".join(
        _spliced(
            sources[stem], node, _pinned_module_names(sources[stem], node), comments=True
        ).rstrip("\n")
        for stem, node in order
    )
    have = existing(path)
    if have is None:
        stems = ", ".join(f"``families/{other}/{s}.py``" for s in sorted(moved_by_stem))
        if shared:
            header = _doc(
                f"Names the {other} family's ``{module}`` shares with other families.",
                f"Used by {', '.join(sorted(users))}. Moved verbatim by "
                f"``scripts/move_family.py`` from {stems}, which import them back where "
                "they use them, so their own code and import paths stay.",
            )
        else:
            header = _doc(
                f"What only the {family} family used from ``{other}.{module}``.",
                f"Only the {family} family uses these, so they live in the family, "
                f"not in the common package. Moved verbatim by ``scripts/move_family.py`` "
                f"from {stems}.",
            )
        text = header + "\nfrom __future__ import annotations\n"
        text += "\n" + "\n".join(import_lines) + "\n\n\n" + body + "\n"
    else:
        text = have.text.rstrip("\n") + "\n\n\n" + body + "\n"
        if import_lines:
            text = _insert_after_imports(text, "\n".join(import_lines))
    files[path] = text
    rel_new = str(path.relative_to(PKG))
    for stem, stem_names in sorted(moved_by_stem.items()):
        src = sources[stem]
        nodes = [node for s, node in order if s == stem]
        rest = _remove_ranges(src.text, [src.segment(node) for node in nodes])
        if shared and (other in users or "core" in users):
            back = f"from ...shared_shapes.{target} import (  # noqa: F401  (shared)\n"
            back += "".join(f"    {n} as {n},\n" for n in sorted(set(stem_names))) + ")\n"
            rest = _insert_after_imports(rest, back)
        files[src.path] = rest
        plan.lost_code.add(src.path)
        plan.moved_helpers.append((f"families/{other}/{stem}.py", rel_new, set(stem_names)))
    plan.lost_code.add(path)
    plan.notes.append(
        f"{'common' if shared else 'family-local'}: {other}/"
        f"{'+'.join(sorted(moved_by_stem))}.py -> {rel_new}: "
        f"{', '.join(moved_names)} (used by {', '.join(sorted(users))})"
    )
    return package, target


def _core_reads(files: dict[Path, str]) -> dict[tuple[str, str], set[str]]:
    """``(family, module) -> names`` that package modules outside ``families/`` read.

    The write-policy middleware, the read-only gate and discovery call family code
    (``from .families.connector.connector import area_write_refusal``, or
    ``connector.area_write_refusal(...)`` through ``from .families.connector import
    connector``). Such a name is used outside its family: it may move to the common
    package (imported back, so the reader's path holds), never into one family.
    """
    out: dict[tuple[str, str], set[str]] = {}
    for path in sorted(PKG.rglob("*.py")):
        if FAMILIES in path.parents or "__pycache__" in path.parts:
            continue
        text = files[path] if path in files else path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        aliases: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            module = node.module or ""
            parts = module.split(".")
            if "families" not in parts:
                continue
            rest = parts[parts.index("families") + 1 :]
            if len(rest) == 2:  # from .families.<f>.<m> import names
                out.setdefault((rest[0], rest[1]), set()).update(a.name for a in node.names)
            elif len(rest) == 1:  # from .families.<f> import <m> [as a]
                for a in node.names:
                    aliases[a.asname or a.name] = (rest[0], a.name)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
            ):
                out.setdefault(aliases[node.value.id], set()).add(node.attr)
    return out


def _family_uses(
    moved_by_stem: dict[str, list[str]],
    closure: set[tuple[str, int]],
    sources: dict[str, Source],
) -> bool:
    """True when the source family's own code reads a moved name outside the moved nodes.

    ``sources`` are the family's modules as the closure parsed them (the node ids match).

    A read is a Name load, in a module of the family, of a local name bound to a moved
    definition there (its own, or a sibling's through ``from .x import n``), or an
    attribute read ``y.n`` of a moved ``n`` of sibling ``x`` imported as ``from . import x
    as y`` (or ``from . import x``).
    """
    for stem, src in sources.items():
        local = set(moved_by_stem.get(stem, []))
        modules: dict[str, str] = {}  # local name -> sibling stem (``from . import x as y``)
        for node in src.tree.body:
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                for alias in node.names:
                    if alias.name in moved_by_stem.get(node.module, []):
                        local.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.level == 1:
                for alias in node.names:
                    modules[alias.asname or alias.name] = alias.name
        for node in src.tree.body:
            if (stem, id(node)) in closure or isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    if child.id in local:
                        return True
                if (
                    isinstance(child, ast.Attribute)
                    and isinstance(child.value, ast.Name)
                    and child.value.id in modules
                    and child.attr in moved_by_stem.get(modules[child.value.id], [])
                ):
                    return True
    return False


def _relevel(line: str, old: int, new: int) -> str:
    """Re-level a relative import line from a module ``old`` dots deep to ``new``."""
    match = re.match(r"from (\.+)(\S*) import (.*)", line)
    if not match:
        return line
    dots = len(match.group(1))
    if dots < old:
        raise Refused(f"cannot re-level {line!r}")
    return f"from {'.' * (dots - old + new)}{match.group(2)} import {match.group(3)}"


def _closure(src: Source, names: set[str]) -> set[str]:
    """The module's own top-level definitions ``names`` need, transitively (names included)."""
    defs = {n: node for node in src.tree.body for n in _defined(node)}
    out: set[str] = set()
    stack = [n for n in names if n in defs]
    while stack:
        name = stack.pop()
        if name in out:
            continue
        out.add(name)
        stack.extend(n for n in _free_names(defs[name]) if n in defs and n not in out)
    return out


def _module_name(src: Source) -> str:
    """The dotted import name of ``src`` (``unifi_fabric.families.connector.connector``)."""
    return ".".join(src.path.relative_to(PKG.parent).with_suffix("").parts)


def _reads_module_dunder(node: ast.AST) -> bool:
    return any(
        isinstance(c, ast.Name) and isinstance(c.ctx, ast.Load) and c.id in _MODULE_DUNDERS
        for c in ast.walk(node)
    )


def _pinned_module_names(src: Source, node: ast.AST) -> list[tuple[int, int, int, str]]:
    """Edits that keep moved code's module identity: ``getLogger(__name__)`` names its module.

    Moved verbatim, ``logging.getLogger(__name__)`` would log under the destination's name
    (an operator-visible channel change). Each such call is written with the original
    module's name; any other read of a module attribute (``__name__``, ``__file__``, ...)
    would change meaning and is refused as hand work.
    """
    pinned: set[int] = set()
    edits: list[tuple[int, int, int, str]] = []
    for call in ast.walk(node):
        if not (isinstance(call, ast.Call) and len(call.args) == 1 and not call.keywords):
            continue
        func = call.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        arg = call.args[0]
        if name == "getLogger" and isinstance(arg, ast.Name) and arg.id == "__name__":
            pinned.add(id(arg))
            end = arg.end_col_offset or arg.col_offset
            edits.append((arg.lineno, arg.col_offset, end, f'"{_module_name(src)}"'))
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id in _MODULE_DUNDERS
            and id(child) not in pinned
        ):
            names = _defined(node) if isinstance(node, ast.stmt) else []
            where = getattr(node, "name", None) or ", ".join(names) or "?"
            raise Refused(
                f"{src.path.name}:{where} reads {child.id}, which would change once moved"
            )
    return edits


def _schema_back(names: Sequence[str], used: set[str]) -> str:
    """The import-back block: a name the module does not read is an explicit re-export."""
    return (
        _SCHEMAS_BACK
        + "".join(f"    {n},\n" if n in used else f"    {n} as {n},\n" for n in names)
        + ")\n"
    )


def _reexport_unread_shapes(plan: Plan, files: dict[Path, str]) -> None:
    """Re-export each moved shape a module no longer reads once its wrappers have moved.

    ``_schemas`` runs before ``_registrar``: a shape only a wrapper's annotation named (a
    ``register`` body still in the module) counted as read. After the wrappers leave, the
    unused-import cleanup would drop that import-back and ``<module>.<NAME>`` would vanish
    (``protect_private.NvrSettings``). Re-judged here, on the module as it is written.
    """
    for path, (block, names) in plan.schema_backs.items():
        text = files.get(path)
        if text is None or block not in text:
            continue
        rest = ast.parse(text.replace(block, "", 1))
        used = {c.id for c in ast.walk(rest) if isinstance(c, ast.Name)}
        files[path] = text.replace(block, _schema_back(names, used), 1)


def _schemas(family: str, plan: Plan, files: dict[Path, str]) -> None:
    """Move F's shapes to ``schemas.py``: signature types and pure constants.

    Signature types (the Protect pilot's schemas, generalised): each class or type alias
    of a tool module that a wrapper's parameter or return annotation names, with the
    classes and aliases those need. Pure constants (the DNS pilot's routes and limits):
    assignments built only from literals and earlier constants. A shape moves only when
    everything it reads moves with it or is imported from outside the family; each module
    imports its shapes back.
    """
    entries, _deps = _loaders()
    steps = {e.module for e in entries if e.family == family}
    # Only the family's tool modules (the loader map's steps); helper modules stay as they are.
    sources = {
        s: src
        for s, src in _family_sources(family, files).items()
        if s not in LAYOUT_STEMS and s in steps
    }
    schemas_path = FAMILIES / family / "schemas.py"
    existing = None
    if schemas_path in files:
        existing = Source(schemas_path, files[schemas_path])
    elif schemas_path.exists():
        existing = Source(schemas_path, schemas_path.read_text(encoding="utf-8"))
    existing_names = set(_bindings(existing.tree)) if existing else set()
    # What other families import from F's modules (and what that needs) stays where it is
    # until their own move takes it out (to the common package or into them).
    reserved: dict[str, set[str]] = {}
    for reader in GEN.family_dirs():
        if reader == family:
            continue
        for _src, _node, other, module, names, _alias in _family_imports(reader, files):
            if other == family and module in sources:
                reserved.setdefault(module, set()).update(_closure(sources[module], set(names)))
    candidates: dict[str, list[tuple[str, ast.stmt, str]]] = {}
    for stem, src in sources.items():
        rebound = {n for c in ast.walk(src.tree) if isinstance(c, ast.Global) for n in c.names}
        stored_later = {
            c.id
            for node in src.tree.body
            if not isinstance(node, (ast.Assign, ast.AnnAssign))
            for c in ast.walk(node)
            if isinstance(c, ast.Name) and isinstance(c.ctx, (ast.Store, ast.Del))
        }
        mutated = {
            c.value.id
            for c in ast.walk(src.tree)
            if isinstance(c, (ast.Subscript, ast.Attribute))
            and isinstance(c.ctx, (ast.Store, ast.Del))
            and isinstance(c.value, ast.Name)
        }
        binds = _bindings(src.tree)
        constants: set[str] = set()
        counts: dict[str, int] = {}
        for node in src.tree.body:
            for n in _defined(node):
                counts[n] = counts.get(n, 0) + 1
        for node in src.tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            names = _assigned_names(node)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(names) != 1 or not all(isinstance(t, ast.Name) for t in targets):
                continue
            name = names[0]
            if name.startswith("__") or name in rebound or name in stored_later or name in mutated:
                continue
            if name in reserved.get(stem, set()):
                plan.notes.append(f"schemas: {stem}.{name} kept: another family's import needs it")
                continue
            if counts.get(name, 0) != 1:
                continue
            if not _pure(node.value, constants):
                continue
            if isinstance(node, ast.AnnAssign):
                extra = [n for n in _free_names(node.annotation) if n not in constants]
                if any(
                    binds.get(n) is None
                    or binds[n].kind != "from"
                    or binds[n].module not in _ANNOTATION_IMPORTS
                    for n in extra
                ):
                    continue
            constants.add(name)
            candidates.setdefault(name, []).append((stem, node, src.segment(node)))
        # Signature types: what the wrappers' annotations name, and what those need.
        defs = {n: node for node in src.tree.body for n in _defined(node)}
        wanted: list[str] = []
        for reg in (n for n in src.tree.body if _is_register(n)):
            ids = _annotation_ids(reg)
            wanted += [c.id for c in ast.walk(reg) if isinstance(c, ast.Name) and id(c) in ids]
        seen: set[str] = set()
        while wanted:
            name = wanted.pop()
            if name in seen or name not in defs or name in constants:
                continue
            seen.add(name)
            node = defs[name]
            if not _is_shape(node) or counts.get(name, 0) != 1:
                continue
            if _reads_module_dunder(node):
                continue  # its module identity would change; it stays
            if name in rebound or name in mutated or name in stored_later:
                continue
            if name in reserved.get(stem, set()):
                plan.notes.append(f"schemas: {stem}.{name} kept: another family's import needs it")
                continue
            candidates.setdefault(name, []).append((stem, node, src.segment(node)))
            wanted += [n for n in _free_names(node) if n in defs]
    # A name two modules bind (differently) stays in each.
    taken: dict[str, tuple[str, ast.stmt]] = {}
    for name, found in candidates.items():
        texts = {"".join(sources[s].lines[a - 1 : b]) for s, _n, (a, b) in found}
        if len(found) > 1 and len(texts) > 1:
            plan.notes.append(f"schemas: {name} differs between {[s for s, _n, _r in found]}; kept")
            continue
        if name in existing_names:
            continue
        taken[name] = (found[0][0], found[0][1])
    # Keep a shape only if all it reads moves too or is imported from outside the family.
    changed = True
    while changed:
        changed = False
        for name, (stem, node) in list(taken.items()):
            binds = _bindings(sources[stem].tree)
            for dep in _free_names(node):
                if dep in taken or dep in existing_names:
                    continue
                binding = binds.get(dep)
                local = (
                    binding is not None
                    and binding.kind == "from"
                    and (binding.module.startswith(".") and binding.module[1:2] != ".")
                )
                if binding is None or binding.kind == "def" or local:
                    del taken[name]
                    changed = True
                    break
    if not taken:
        return
    by_stem: dict[str, list[str]] = {}
    for name, (stem, _node) in taken.items():
        by_stem.setdefault(stem, []).append(name)
    blocks: list[tuple[int, str, str]] = []
    typing_names: dict[str, Binding] = {}
    for stem in sorted(by_stem):
        src = sources[stem]
        binds = _bindings(src.tree)
        nodes = [taken[n][1] for n in by_stem[stem]]
        ranges = []
        previous_end = -1
        for node in sorted(nodes, key=lambda n: n.lineno):
            a, b = src.segment(node)
            ranges.append((a, b))
            text = "".join(src.lines[a - 1 : b])
            if blocks and blocks[-1][2] == stem and a == previous_end + 1:
                # Adjacent in the module: keep them together, as they were.
                blocks[-1] = (blocks[-1][0], blocks[-1][1].rstrip("\n") + "\n" + text, stem)
            else:
                blocks.append((sorted(by_stem).index(stem), text, stem))
            previous_end = b
            for n in _free_names(node):
                if n in binds and binds[n].kind != "def" and n not in taken:
                    typing_names[n] = binds[n]
        rest = _remove_ranges(src.text, ranges)
        moved = sorted(by_stem[stem])
        rest_tree = ast.parse(rest)
        used = {c.id for c in ast.walk(rest_tree) if isinstance(c, ast.Name)}
        # A name the module itself no longer reads is re-exported explicitly (``X as X``),
        # so ``<module>.X`` stays for the code and tests that read it there.
        back = _schema_back(moved, used)
        files[src.path] = _insert_after_imports(rest, back)
        plan.schema_backs[src.path] = (back, moved)
        plan.lost_code.add(src.path)
        plan.notes.append(f"schemas: {stem}.py -> schemas.py: {', '.join(moved)}")
        # A shape's keys follow it (``families/<f>/<stem>.py:RadioChanges._no_null_fields``).
        plan.moved_helpers.append(
            (f"families/{family}/{stem}.py", f"families/{family}/schemas.py", set(moved))
        )
    body = "\n".join(text.rstrip("\n") + "\n" for _i, text, _s in blocks)
    imports = sorted({b.line(n) for n, b in typing_names.items()})
    if existing is None:
        text = (
            _doc(
                f"The {family} family's shapes: parameter types, routes and limits "
                "(the family-owned layout).",
                "Moved verbatim by ``scripts/move_family.py`` from the family's modules, "
                "which import them back.",
            )
            + "\nfrom __future__ import annotations\n"
            + ("\n" + "\n".join(imports) + "\n" if imports else "")
            + "\n"
            + body
        )
    else:
        text = existing.text.rstrip("\n") + "\n\n" + body
        if imports:
            text = _insert_after_imports(text, "\n".join(imports))
    files[schemas_path] = text
    plan.lost_code.add(schemas_path)


def _is_shape(node: ast.stmt) -> bool:
    """A class or a type alias (``X = Literal[...]``, ``type X = ...``, ``X: TypeAlias = ...``)."""
    if isinstance(node, (ast.ClassDef, ast.TypeAlias)):
        return True
    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and isinstance(node.value, (ast.Subscript, ast.BinOp, ast.Attribute))
        )
    return False


def _annotation_ids(node: ast.AST) -> set[int]:
    """``id()`` of every Name inside a parameter or return annotation under ``node``."""
    out: set[int] = set()
    for fn in ast.walk(node):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        args = fn.args
        anns = [a.annotation for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
        anns += [a.annotation for a in (args.vararg, args.kwarg) if a is not None]
        if not isinstance(fn, ast.Lambda):
            anns.append(fn.returns)
        for ann in anns:
            if ann is not None:
                out.update(id(c) for c in ast.walk(ann) if isinstance(c, ast.Name))
    return out


def _self_aliases(src: Source) -> set[str]:
    """Top-level names bound to the module itself (``_impl = sys.modules[__name__]``)."""
    out: set[str] = set()
    for node in src.tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            value, target = node.value, node.targets[0]
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Subscript)
                and ast.unparse(value) == "sys.modules[__name__]"
            ):
                out.add(target.id)
    return out


def _bound_in(node: ast.AST) -> set[str]:
    """Every name ``node`` binds anywhere inside it (parameters, stores, defs, handlers)."""
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.arg):
            out.add(child.arg)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            out.add(child.id)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(child.name)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            out.add(child.name)
    return out


def _resolve(
    src: Source,
    reg: ast.FunctionDef,
    sources: dict[str, Source],
    qualify: frozenset[str] = frozenset(),
) -> tuple[list[tuple[int, int, int, str]], dict[str, str]]:
    """How the register function ``reg`` reads each name once it lives in ``registrar.py``.

    The Protect pilot's rule, generalised (handlers are always called through a module
    alias). Per wrapper, every free name is one of:

    * defined in the wrapper's module: read as ``<module>.<name>`` (a ``sys.modules``
      self-alias such as ``_impl`` reads as the module itself);
    * imported from a sibling family module (``from .handlers import x``): ``handlers.x``;
    * a family module already (``from . import protect``): kept, imported the same way;
    * anything else (stdlib, fastmcp, pydantic, the package's shared code, ``schemas``):
      imported the way the module imports it.

    Annotations are not rewritten (they are the input schema): their names are imported
    directly, except a name in ``qualify`` (two modules define it differently), which
    reads as ``<module>.<name>``. Returns the edits ``(line, col, end_col, text)`` and the imports
    ``{local name: import line}``. A wrapper local that shadows a module alias is refused.
    """
    binds = _bindings(src.tree)
    selfs = _self_aliases(src)
    annotations = _annotation_ids(reg)
    scope = {a.arg for a in (*reg.args.posonlyargs, *reg.args.args, *reg.args.kwonlyargs)}
    for stmt in reg.body:
        scope.update(_defined(stmt))
    edits: list[tuple[int, int, int, str]] = []
    imports: dict[str, str] = {}

    def need(local: str, line: str) -> None:
        if imports.setdefault(local, line) != line:
            raise Refused(
                f"{src.path.name}:{reg.name}: {local!r} is {imports[local]!r} and {line!r}"
            )

    parts: list[ast.AST] = [*reg.body, reg.args]
    if reg.returns is not None:
        parts.append(reg.returns)
    for part in parts:
        free = set(_free_names(part)) - scope
        bound = _bound_in(part) if isinstance(part, ast.stmt) else set()
        aliases_here: set[str] = set()
        for child in ast.walk(part):
            if not (isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)):
                continue
            name = child.id
            if name not in free:
                continue
            binding = binds.get(name)
            if binding is None:
                raise Refused(f"{src.path.name}:{reg.name}: {name!r} is not bound in the module")
            in_annotation = id(child) in annotations
            end = child.end_col_offset or child.col_offset
            spot = (child.lineno, child.col_offset, end)
            if binding.kind == "def":
                if src.stem == "registrar":
                    continue  # a registrar helper: it stays beside the functions
                if name in selfs:
                    edits.append((*spot, src.stem))
                    need(src.stem, f"from . import {src.stem}")
                    aliases_here.add(src.stem)
                elif in_annotation and name not in qualify:
                    need(name, f"from .{src.stem} import {name}")
                else:
                    edits.append((*spot, f"{src.stem}.{name}"))
                    need(src.stem, f"from . import {src.stem}")
                    aliases_here.add(src.stem)
                continue
            if binding.kind == "from":
                module = binding.module
                sibling = module[1:] if module.startswith(".") and module[1:2] != "." else ""
                if module == ".":
                    need(name, binding.line(name))
                    continue
                if sibling and sibling in sources and sibling != "schemas" and not in_annotation:
                    edits.append((*spot, f"{sibling}.{binding.name}"))
                    need(sibling, f"from . import {sibling}")
                    aliases_here.add(sibling)
                    continue
            need(name, binding.line(name))
        shadowed = sorted(aliases_here & bound)
        if shadowed:
            raise Refused(f"{src.path.name}:{reg.name}: a wrapper local shadows {shadowed}")
    edits += _unpacked_deps(src, reg, selfs)
    return edits, imports


def _unpacked_deps(
    src: Source, reg: ast.FunctionDef, selfs: set[str]
) -> list[tuple[int, int, int, str]]:
    """Edits writing ``_impl.f(*deps_fn(), x)`` as ``client, registry = deps_fn()`` and a call.

    A ``sys.modules`` self-alias is typed ``Any``, so mypy never checked such a call; once it
    reads ``<module>.f`` it is typed, and mypy cannot spread ``*deps_fn()`` (``Any``) before
    more positional arguments (``Too many arguments``). The loader's ``deps_fn`` returns
    ``(client, registry)``, the form the other wrappers already unpack. Only a call that is a
    statement's whole value is rewritten; anything else, or a wrapper that already reads
    ``client`` or ``registry``, is refused as hand work.
    """
    params = {a.arg for a in (*reg.args.posonlyargs, *reg.args.args)}
    parents = {id(c): p for p in ast.walk(reg) for c in ast.iter_child_nodes(p)}
    edits: list[tuple[int, int, int, str]] = []
    for call in ast.walk(reg):
        if not (isinstance(call, ast.Call) and len(call.args) >= 2):
            continue
        star, func = call.args[0], call.func
        if not (
            isinstance(star, ast.Starred)
            and isinstance(star.value, ast.Call)
            and isinstance(star.value.func, ast.Name)
            and star.value.func.id in params
            and not star.value.args
            and not star.value.keywords
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in selfs
        ):
            continue
        deps = star.value.func.id
        where = f"{src.path.name}:{reg.name}: {func.value.id}.{func.attr}(*{deps}(), ...)"
        value: ast.AST = call
        parent = parents.get(id(value))
        if isinstance(parent, ast.Await):
            value, parent = parent, parents.get(id(parent))
        if not (
            isinstance(parent, (ast.Return, ast.Expr, ast.Assign, ast.AnnAssign))
            and parent.value is value
        ):
            raise Refused(f"{where} is not a statement's whole value")
        wrapper = parents.get(id(parent))
        while wrapper is not None and not isinstance(
            wrapper, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            wrapper = parents.get(id(wrapper))
        if wrapper is None or wrapper is reg:
            raise Refused(f"{where} is not inside a tool wrapper")
        taken = _bound_in(wrapper) | set(_free_names(wrapper))
        if taken & {"client", "registry"} or star.lineno != star.end_lineno:
            raise Refused(f"{where}: cannot unpack into client, registry")
        indent = " " * parent.col_offset
        edits.append(
            (
                parent.lineno,
                parent.col_offset,
                parent.col_offset,
                f"client, registry = {deps}()\n{indent}",
            )
        )
        edits.append((star.lineno, star.col_offset, star.end_col_offset or 0, "client, registry"))
    return edits


def _spliced(
    src: Source, node: ast.stmt, edits: list[tuple[int, int, int, str]], comments: bool = False
) -> str:
    """The statement's source with each edit applied (byte columns, as ``ast`` gives them).

    With ``comments``, from its leading ``#`` comments on (:meth:`Source.segment`).
    """
    a, b = src.segment(node) if comments else (_stmt_start(node), node.end_lineno or node.lineno)
    lines = [line.encode("utf-8") for line in src.lines[a - 1 : b]]
    for lineno, col, end, text in sorted(edits, reverse=True):
        raw = lines[lineno - a]
        lines[lineno - a] = raw[:col] + text.encode("utf-8") + raw[end:]
    return b"".join(lines).decode("utf-8")


class _Collision(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def _registrar(family: str, entries: list[Any], plan: Plan, files: dict[Path, str]) -> list[Any]:
    """Move F's register functions to ``registrar.py``; return the repointed entries.

    A name two of F's modules define differently and their wrappers both import reads
    as ``<module>.<name>`` in each (retried until no import collides).
    """
    qualify: frozenset[str] = frozenset()
    while True:
        try:
            return _registrar_once(family, entries, plan, files, qualify)
        except _Collision as exc:
            if exc.name in qualify:
                raise Refused(f"registrar.py: {exc.name!r} still collides") from exc
            qualify = qualify | {exc.name}
            plan.notes.append(f"registrar: {exc.name} is defined in two modules; qualified")


def _registrar_once(
    family: str,
    entries: list[Any],
    plan: Plan,
    files: dict[Path, str],
    qualify: frozenset[str],
) -> list[Any]:
    own = [e for e in entries if e.family == family]
    target = [(_numbered(i), e) for i, e in enumerate(own)]
    sources = _family_sources(family, files)
    current = sources.get("registrar")
    if (
        current is not None
        and all(e.module == "registrar" and e.function == name for name, e in target)
        and not any(_resolve(current, n, sources)[0] for n in current.tree.body if _is_register(n))
    ):
        return entries
    path = FAMILIES / family / "registrar.py"
    kept_top: list[str] = []
    imports: dict[str, str] = {}
    if current is not None:
        for node in current.tree.body:
            if _is_register(node) or isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if node is current.tree.body[0] and isinstance(node, ast.Expr):
                continue
            a, b = current.segment(node)
            kept_top.append("".join(current.lines[a - 1 : b]))
            for free in _free_names(node):
                binding = _bindings(current.tree).get(free)
                if binding is not None and binding.kind != "def":
                    imports.setdefault(free, binding.line(free))
    functions: list[str] = []
    removals: dict[str, list[tuple[int, int]]] = {}
    for name, entry in target:
        src = sources[entry.module]
        node = next(n for n in src.tree.body if _is_register(n) and n.name == entry.function)
        edits, needed = _resolve(src, node, sources, qualify)
        edits = edits + _pinned_module_names(src, node)
        for local, line in needed.items():
            if imports.setdefault(local, line) != line:
                both = (imports[local], line)
                if all(re.fullmatch(rf"from \.\w+ import {local}", x) for x in both):
                    raise _Collision(local)
                raise Refused(f"registrar.py: {local!r} is {imports[local]!r} and {line!r}")
        text = _spliced(src, node, edits)
        if node.name != name:
            text = re.sub(rf"\bdef {node.name}\(", f"def {name}(", text, count=1)
        functions.append(text.rstrip("\n") + "\n")
        removals.setdefault(entry.module, []).append((_stmt_start(node), node.end_lineno or 0))
        if edits:
            plan.notes.append(
                f"module alias: {src.path.name}:{node.name}: {len(edits)} reads qualified"
            )
    for stem, ranges in removals.items():
        if stem == "registrar":
            continue
        src = sources[stem]
        extra: list[tuple[int, int]] = []
        # The trailing self-import the server.py wrapper codemod added for its wrappers.
        for node in src.tree.body:
            if (
                isinstance(node, ast.ImportFrom)
                and node.level == 1
                and not node.module
                and [a.name for a in node.names] == [stem]
            ):
                extra.append(src.segment(node))
        files[src.path] = _remove_ranges(src.text, ranges + extra)
        plan.lost_code.add(src.path)
        plan.notes.append(
            f"registrar: {stem}.py:{', '.join(e.function for e in own if e.module == stem)} "
            f"-> registrar.py"
        )
    for local, line in (
        ("Callable", "from collections.abc import Callable"),
        ("Any", "from typing import Any"),
        ("FastMCP", "from fastmcp import FastMCP"),
    ):
        imports.setdefault(local, line)
    header = (
        _doc(
            f"The {family} family registrar: its tool wrappers, in registration order "
            "(the family-owned layout).",
            "The loader map (``catalog/loaders.py``) runs each ``register`` / "
            "``register_<n>`` below at its place in the ``tools/list`` order, with the "
            "``origin`` its tools are indexed under. The wrappers are the tools' public "
            "surface (names, annotations, docstrings, signatures), moved by "
            "``scripts/move_family.py``; each calls its handler through the handler's "
            "module, so a patched handler still applies (``handlers.py`` indexes them).",
        )
        + "\nfrom __future__ import annotations\n\n"
    )
    text = header + "\n".join(sorted(set(imports.values()))) + "\n"
    if kept_top:
        text += "\n\n" + "\n\n".join(k.rstrip("\n") for k in kept_top) + "\n"
    text += "\n\n" + "\n\n".join(f.rstrip("\n") + "\n" for f in functions)
    files[path] = text
    plan.lost_code.add(path)
    for _name, entry in target:
        if entry.module == "registrar":
            continue
        node = next(
            n
            for n in sources[entry.module].tree.body
            if _is_register(n) and n.name == entry.function
        )
        names = plan.moved_wrappers.setdefault(f"families/{family}/{entry.module}.py", set())
        for tool in ast.walk(node):
            if isinstance(tool, (ast.AsyncFunctionDef, ast.FunctionDef)) and _is_tool(tool):
                names.update({tool.name, _tool_name(tool)})
    by_old = {(e.module, e.function): name for name, e in target}
    return [
        e._replace(module="registrar", function=by_old[(e.module, e.function)])
        if e.family == family and (e.module, e.function) in by_old
        else e
        for e in entries
    ]


def _handler_index(family: str, plan: Plan, files: dict[Path, str]) -> dict[str, str]:
    """The tool -> ``module:function`` index of the family's registrar wrappers."""
    path = FAMILIES / family / "registrar.py"
    text = files.get(path, path.read_text(encoding="utf-8") if path.exists() else "")
    tree = ast.parse(text)
    binds = _bindings(tree)
    family_modules = {
        p.stem for p in (FAMILIES / family).glob("*.py") if p.name != "__init__.py"
    } | {p.stem for p in files if p.parent == FAMILIES / family}
    index: dict[str, str] = {}
    for reg in (n for n in tree.body if _is_register(n)):
        for tool in (n for n in ast.walk(reg) if _is_tool(n)):
            if not isinstance(tool, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            calls = sorted(
                (c for c in ast.walk(tool) if isinstance(c, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            target = f"registrar:{reg.name}.{tool.name}"
            for call in calls:
                func = call.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    b = binds.get(func.value.id)
                    if b and b.kind == "from" and b.module == "." and b.name in family_modules:
                        target = f"{b.name}:{func.attr}"
                        break
                if isinstance(func, ast.Name):
                    b = binds.get(func.id)
                    if (
                        b
                        and b.kind == "from"
                        and b.module.startswith(".")
                        and not b.module.startswith("..")
                        and b.module[1:] in family_modules
                    ):
                        target = f"{b.module[1:]}:{b.name}"
                        break
            index[_tool_name(tool)] = _defining(family, target, files)
    return index


def _defining(family: str, target: str, files: dict[Path, str]) -> str:
    """``module:function`` of where a handler is defined, one re-export hop away.

    A move that takes a handler to the common package (or a family's private
    ``_<module>_shared.py``) leaves its module importing it back: the index names the
    defining module (``shared_shapes._protect_shared:list_cameras``), as a reader of the
    index needs.
    """
    module, _, name = target.partition(":")
    if module == "registrar" or "." in name:
        return target
    path = FAMILIES / family / f"{module}.py"
    text = files.get(path, path.read_text(encoding="utf-8") if path.exists() else "")
    if not text:
        return target
    binding = _bindings(ast.parse(text)).get(name)
    if binding is None or binding.kind != "from":
        return target
    if binding.module.startswith("...shared_shapes."):
        return f"shared_shapes.{binding.module.removeprefix('...shared_shapes.')}:{binding.name}"
    if binding.module.startswith("._") and binding.module.endswith("_shared"):
        return f"{binding.module[1:]}:{binding.name}"
    return target


def _refresh_other_indexes(family: str, plan: Plan, files: dict[Path, str]) -> None:
    """Regenerate the handler index of each moved family whose modules this move edited."""
    others = sorted(
        {
            p.parent.name
            for p in files
            if p.suffix == ".py" and p.parent.parent == FAMILIES and p.parent.name != family
        }
    )
    for other in others:
        handlers = FAMILIES / other / "handlers.py"
        current = files.get(handlers, handlers.read_text("utf-8") if handlers.exists() else "")
        if HANDLERS_BEGIN not in current or not (FAMILIES / other / "registrar.py").exists():
            continue
        before = current
        _write_handler_index(other, _handler_index(other, plan, files), plan, files)
        if files.get(handlers) != before:
            plan.notes.append(f"handler index: {other} follows its handlers to the common package")


def _write_handler_index(
    family: str, index: dict[str, str], plan: Plan, files: dict[Path, str]
) -> None:
    path = FAMILIES / family / "handlers.py"
    current = files.get(path, path.read_text(encoding="utf-8") if path.exists() else None)
    modules = sorted({ref.split(":", 1)[0] for ref in index.values()})
    block = (
        f"{HANDLERS_BEGIN}\n"
        "#: The family's handler modules (they keep their import paths).\n"
        "HANDLER_MODULES: tuple[str, ...] = ("
        + ("".join(f'\n    "{m}",' for m in modules) + "\n" if modules else "")
        + ")\n\n"
        "#: Each tool of the family and the ``module:function`` its wrapper calls\n"
        "#: (``registrar:<register>.<wrapper>`` when the wrapper is the handler itself).\n"
        "HANDLERS: dict[str, str] = {"
        + ("".join(f'\n    "{t}": "{index[t]}",' for t in sorted(index)) + "\n" if index else "")
        + "}\n"
        f"{HANDLERS_END}\n"
    )
    if current is None:
        text = (
            _doc(
                f"The {family} family's handlers (the family-owned layout).",
                "The implementations live in the family's modules, whose import paths stay "
                "(other families and the tests import them); this index names, for every "
                "tool, the handler its wrapper in ``registrar.py`` calls. Generated by "
                "``scripts/move_family.py``; its ``--check`` keeps it current.",
            )
            + "\nfrom __future__ import annotations\n\n"
            + block
        )
    elif HANDLERS_BEGIN in current:
        head, _, tail = current.partition(HANDLERS_BEGIN)
        _, _, after = tail.partition(HANDLERS_END + "\n")
        text = head + block + after
    else:
        text = current.rstrip("\n") + "\n\n\n" + block
    files[path] = text


#: The generated family test's schemas check (only for a family with a ``schemas.py``).
_SCHEMAS_TEST = """def test_constants_are_shared_with_schemas():
    schemas = importlib.import_module(f"unifi_fabric.families.{FAMILY}.schemas")
    for path in sorted(DIRECTORY.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == "schemas":
                module = importlib.import_module(f"unifi_fabric.families.{FAMILY}.{path.stem}")
                for alias in node.names:
                    assert getattr(module, alias.asname or alias.name) is getattr(
                        schemas, alias.name
                    ), (path.name, alias.name)


"""


def _family_test(
    family: str, entries: list[Any], files: dict[Path, str], kept: set[tuple[str, str]]
) -> None:
    own = [e for e in entries if e.family == family]
    steps = "".join(f'    ("{e.module}", "{e.function}", "{e.deps}", "{e.origin}"),\n' for e in own)
    kept = "{" + "".join(f"\n    {pair!r}," for pair in sorted(kept)) + ("\n}" if kept else "}")
    if not kept.strip("{}"):
        kept = "set()"
    path = TESTS / f"test_{family}_family.py"
    schemas_path = FAMILIES / family / "schemas.py"
    # Only a family the move gave (or that has) a schemas.py gets its schemas test: a
    # family with no signature types and no constants has none to import.
    has_schemas = schemas_path in files or schemas_path.exists()
    ast_import = "import ast\n" if has_schemas else ""
    schemas_line = (
        "the family's shapes are the same objects where they\nwere and in ``schemas.py``, "
        if has_schemas
        else ""
    )
    schemas_test = _SCHEMAS_TEST if has_schemas else ""
    files[path] = f'''"""The {family} family in the family-owned layout.

Generated by ``scripts/move_family.py --family {family}``: the loader map runs
the family's registrar at each step's place, every tool keeps its ``MODULE_INDEX`` stem
(the step's origin), the handler index resolves, {schemas_line}and no family module
imports another family (the shared code is in the common package).
"""

from __future__ import annotations

{ast_import}import asyncio
import importlib
import importlib.util
import inspect
import sys
from pathlib import Path

from unifi_fabric import server
from unifi_fabric.catalog import META_FAMILY, load_catalog
from unifi_fabric.catalog.loaders import COMMON_PACKAGE, LOADERS
from unifi_fabric.families import build_family_index, build_module_index, tool_function_module
from unifi_fabric.families.{family} import handlers, registrar

FAMILY = "{family}"
ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "src" / "unifi_fabric" / "families" / FAMILY

#: The family's loader steps, in order: (module, function, deps, origin).
STEPS = (
{steps})


def _move_family():
    path = ROOT / "scripts" / "move_family.py"
    spec = importlib.util.spec_from_file_location("move_family", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("move_family", module)
    spec.loader.exec_module(module)
    return module


def _tools():
    return {{t.name: t for t in asyncio.run(server.mcp.list_tools(run_middleware=False))}}


def test_loader_steps_run_the_registrar():
    own = [e for e in LOADERS if e.family == FAMILY]
    assert [(e.module, e.function, e.deps, e.origin) for e in own] == list(STEPS)
    for entry in own:
        assert callable(getattr(registrar, entry.function))


def test_tools_are_registered_by_the_registrar_and_keep_their_index():
    tools = _tools()
    catalog = load_catalog().by_name()
    families, modules = build_family_index(), build_module_index()
    origins = {{origin for _m, _f, _d, origin in STEPS}}
    registered = {{
        name
        for name, tool in tools.items()
        if inspect.unwrap(tool.fn).__module__ == registrar.__name__
    }}
    assert registered == set(handlers.HANDLERS)
    for name in sorted(registered):
        fn = inspect.unwrap(tools[name].fn)
        # The discovery vocabulary keys on the step's origin, never on "registrar".
        assert tool_function_module(fn) in origins, name
        assert modules[name] == tool_function_module(fn), name
        if catalog[name].family != META_FAMILY:  # a legacy selection meta tool keeps its family
            assert families[name] == catalog[name].family, name
        assert catalog[name].id == f"{{catalog[name].family}}.{{name}}", name


def test_server_keeps_each_origin_module():
    # server.<origin> stays bound to the origin module while that module exists.
    for _m, _f, _d, origin in STEPS:
        if (DIRECTORY / f"{{origin}}.py").exists():
            module = importlib.import_module(f"unifi_fabric.families.{{FAMILY}}.{{origin}}")
            assert getattr(server, origin) is module, origin


def test_handler_index_resolves():
    for tool, ref in handlers.HANDLERS.items():
        module, _, attr = ref.partition(":")
        assert module in handlers.HANDLER_MODULES or module == "registrar", (tool, ref)
        if module == "registrar":
            continue
        # A handler another family's move took to the common package is named there.
        shared = module.startswith("shared_shapes.")
        dotted = module if shared else f"families.{{FAMILY}}.{{module}}"
        target = importlib.import_module(f"unifi_fabric.{{dotted}}")
        assert callable(getattr(target, attr)), (tool, ref)


{schemas_test}#: Imports of other families the move kept (``--keep-cross-family``: hand work left).
KEPT_CROSS_FAMILY: set[tuple[str, str]] = {kept}


def test_no_cross_family_import_but_the_kept_ones():
    found = {{(file, other) for file, _line, other in _move_family().family_imports(FAMILY)}}
    assert found == KEPT_CROSS_FAMILY, f"move these to {{COMMON_PACKAGE}}: {{found}}"
'''


def _kept_cross(family: str, files: dict[Path, str]) -> set[tuple[str, str]]:
    return {
        (f"families/{family}/{src.path.name}", other)
        for src, _node, other, _module, _names, _alias in _family_imports(family, files)
    }


#: Where a wrapper's ``families/<F>/<stem>.py:<register>.<wrapper>`` key may be cited (the
#: refusal registry in ``refusals.py``, its tests, the docs ledgers).
KEY_ROOTS = ("src/unifi_fabric", "tests", "docs", "scripts")
KEY_SUFFIXES = (".py", ".json", ".md")


def _rewrite_keys(family: str, moved: dict[tuple[str, str], str], files: dict[Path, str]) -> None:
    """Follow each moved wrapper's ``file:qualname`` key (refusal registry, ledgers)."""
    if not moved:
        return
    alternatives = "|".join(
        re.escape(f"families/{family}/{stem}.py:{function}.")
        for stem, function in sorted(moved, key=lambda k: (-len(k[1]), k))
    )
    pattern = re.compile(alternatives)
    by_text = {
        f"families/{family}/{stem}.py:{function}.": f"families/{family}/registrar.py:{new}."
        for (stem, function), new in moved.items()
    }
    for root in KEY_ROOTS:
        for path in sorted((ROOT / root).rglob("*")):
            if path.suffix not in KEY_SUFFIXES or not path.is_file() or path == Path(__file__):
                continue
            text = files[path] if path in files else path.read_text(encoding="utf-8")
            new = pattern.sub(lambda m: by_text[m.group(0)], text)
            if new != text:
                files[path] = new


def _key_files(files: dict[Path, str]) -> Iterable[tuple[Path, str]]:
    """Every text file a ``file:qualname`` key may sit in, with its (planned) text."""
    for root in KEY_ROOTS:
        for path in sorted((ROOT / root).rglob("*")):
            if path.suffix not in KEY_SUFFIXES or not path.is_file() or path == Path(__file__):
                continue
            if "__pycache__" in path.parts:
                continue
            yield path, files[path] if path in files else path.read_text(encoding="utf-8")


def _rewrite_helper_keys(plan: Plan, files: dict[Path, str]) -> None:
    """Follow each moved helper's ``<file>:<name>[.<inner>]`` key to its new file.

    The refusal registry, the redaction and silent-filter allowlists and the like key a
    function by ``families/<x>/<module>.py:<qualname>``. A key whose qualname starts
    with a moved helper's name now names the file the helper moved to. A bare file
    reference (``"families/<x>/<module>.py"`` alone, keyed by something else) cannot be
    told apart from one about the code that stayed: each is printed as a hand check.
    """
    if not plan.moved_helpers:
        return
    # (old file, name) -> new file: two groups out of one module may go to two targets.
    new_of: dict[tuple[str, str], str] = {}
    for old, new, names in plan.moved_helpers:
        for name in names:
            new_of[(old, name)] = new
    olds = sorted({old for old, _name in new_of})
    names = sorted({name for _old, name in new_of}, key=lambda n: (-len(n), n))
    pattern = re.compile(
        "(?P<old>" + "|".join(re.escape(o) for o in olds) + "):"
        "(?P<name>" + "|".join(re.escape(n) for n in names) + r")\b"
    )

    def repl(match: re.Match[str]) -> str:
        new = new_of.get((match.group("old"), match.group("name")))
        return match.group(0) if new is None else f"{new}:{match.group('name')}"

    # The tuple form of a key: ("families/<x>/<module>.py", "<name>[.<inner>]", ...).
    pair = re.compile(
        "(?P<q1>[\"'])(?P<old>" + "|".join(re.escape(o) for o in olds) + ")(?P=q1)"
        "(?P<sep>\\s*,\\s*)(?P<q2>[\"'])"
        "(?P<name>" + "|".join(re.escape(n) for n in names) + r")(?=[.\"'])"
    )

    def repl_pair(match: re.Match[str]) -> str:
        new = new_of.get((match.group("old"), match.group("name")))
        if new is None:
            return match.group(0)
        q1, sep, q2 = match.group("q1"), match.group("sep"), match.group("q2")
        return f"{q1}{new}{q1}{sep}{q2}{match.group('name')}"

    bare = re.compile("|".join(re.escape(f'"{old}"') for old in olds))
    for path, text in _key_files(files):
        new = pair.sub(repl_pair, pattern.sub(repl, text))
        if new != text:
            files[path] = new
        for lineno, line in enumerate(new.splitlines(), 1):
            if bare.search(line):
                plan.notes.append(
                    f"hand check: {path.relative_to(ROOT)}:{lineno} names a module helpers "
                    f"moved out of: {line.strip()[:90]}"
                )


def _register_imports(
    tree: ast.Module, package: str, moved: dict[tuple[str, str], str]
) -> list[tuple[int, int, str]]:
    """``from <package>.<module> import register as r`` of moved steps, re-pointed.

    Returns ``(first line, last line, replacement text)``: the same local names, imported
    from the family registrar (the other names stay where they were).
    """
    out: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.level or not node.module:
            continue
        if not node.module.startswith(f"{package}."):
            continue
        stem = node.module[len(package) + 1 :]
        steps = [a for a in node.names if (stem, a.name) in moved]
        if not steps:
            continue
        indent = " " * node.col_offset
        kept = [a for a in node.names if a not in steps]
        lines = []
        if kept:
            names = ", ".join(a.name + (f" as {a.asname}" if a.asname else "") for a in kept)
            lines.append(f"{indent}from {node.module} import {names}")
        names = ", ".join(f"{moved[(stem, a.name)]} as {a.asname or a.name}" for a in steps)
        lines.append(f"{indent}from {package}.registrar import {names}")
        out.append((node.lineno, node.end_lineno or node.lineno, "\n".join(lines) + "\n"))
    return out


def _rewrite_register_calls(
    family: str, moved: dict[tuple[str, str], str], plan: Plan, files: dict[Path, str]
) -> None:
    """Point ``<module>.register*`` reads in tests and scripts at the family registrar.

    A test that registers a module's tools itself (``ndo.register(mcp, deps)``, or the
    function in a tuple) names a function that moved: any read of ``<alias>.register*``
    where ``<alias>`` is an import of a moved module of the family (any scope, any
    ``as`` name), or ``server.<module>.register*``, becomes
    ``<family>_registrar.<new name>``, imported once at module level. A ``register*`` read
    on any other name in a file that imports a moved module (a loop variable over
    modules) cannot be resolved statically: it is printed as a hand check.
    """
    if not moved:
        return
    package = f"unifi_fabric.families.{family}"
    stems = {stem for stem, _function in moved}
    alias = f"{family}_registrar"
    import_line = f"from {package} import registrar as {alias}"
    for root in ("tests", "scripts", "docs"):
        for path in sorted((ROOT / root).rglob("*.py")):
            if path == Path(__file__) or "__pycache__" in path.parts:
                continue
            text = files[path] if path in files else path.read_text(encoding="utf-8")
            if package not in text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            modules: dict[str, str] = {}
            servers: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and not node.level:
                    for a in node.names:
                        if node.module == package and a.name in stems:
                            modules[a.asname or a.name] = a.name
                        if node.module == "unifi_fabric" and a.name == "server":
                            servers.add(a.asname or a.name)
                elif isinstance(node, ast.Import):
                    for a in node.names:
                        stem = a.name.removeprefix(f"{package}.")
                        if a.asname and stem in stems and a.name == f"{package}.{stem}":
                            modules[a.asname] = stem
            imports = _register_imports(tree, package, moved)
            if not modules and not servers and not imports:
                continue
            imported = {
                a.asname or a.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for a in node.names
            }
            edits: list[tuple[int, int, int, str]] = []
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Attribute) and _REGISTER_RE.fullmatch(node.attr)):
                    continue
                value, stem = node.value, None
                if isinstance(value, ast.Name) and value.id in modules:
                    stem = modules[value.id]
                elif (
                    isinstance(value, ast.Attribute)
                    and isinstance(value.value, ast.Name)
                    and value.value.id in servers
                    and value.attr in stems
                ):
                    stem = value.attr
                new = moved.get((stem, node.attr)) if stem else None
                if new is not None and node.lineno == node.end_lineno:
                    end = node.end_col_offset or node.col_offset
                    edits.append((node.lineno, node.col_offset, end, f"{alias}.{new}"))
                elif modules and isinstance(value, ast.Name) and value.id not in imported:
                    plan.notes.append(
                        f"hand check: {path.relative_to(ROOT)}:{node.lineno}: "
                        f"{ast.unparse(node)} may name a moved {family} register step"
                    )
            if not edits and not imports:
                continue
            lines = [line.encode("utf-8") for line in text.splitlines(keepends=True)]
            for lineno, col, end, new_text in sorted(edits, reverse=True):
                raw = lines[lineno - 1]
                lines[lineno - 1] = raw[:col] + new_text.encode("utf-8") + raw[end:]
            # ``from <pkg>.<stem> import register as r``: the same local name, from the registrar.
            for first, last, replacement in sorted(imports, reverse=True):
                lines[first - 1 : last] = [replacement.encode("utf-8")]
            text = b"".join(lines).decode("utf-8")
            if edits and import_line not in text:
                text = _insert_after_imports(text, import_line)
            files[path] = text
            plan.lost_code.add(path)  # an alias import may now be unused (ruff F401)
            plan.notes.append(
                f"register calls: {path.relative_to(ROOT)}: {len(edits) + len(imports)} -> "
                f"{alias}.<step>"
            )


def plan_family(family: str, keep_cross_family: bool = False) -> Plan:
    plan = Plan(family)
    if family not in GEN.family_dirs():
        raise SystemExit(f"no family directory {family!r} (have {GEN.family_dirs()})")
    entries, dependencies = _loaders()
    files: dict[Path, str] = {}
    try:
        if keep_cross_family:
            for file, other in sorted(_kept_cross(family, files)):
                plan.notes.append(f"cross-family KEPT (hand work): {file} imports {other}")
        else:
            _cross_family(family, plan, files)
        _schemas(family, plan, files)
        _rewrite_helper_keys(plan, files)
        before = {(e.module, e.function): i for i, e in enumerate(entries) if e.family == family}
        entries = _registrar(family, entries, plan, files)
        moved = {
            key: entries[i].function
            for key, i in before.items()
            if key[0] != "registrar" or entries[i].function != key[1]
        }
        _rewrite_keys(family, moved, files)
        _rewrite_register_calls(family, moved, plan, files)
        index = _handler_index(family, plan, files)
        _write_handler_index(family, index, plan, files)
        _refresh_other_indexes(family, plan, files)
        _reexport_unread_shapes(plan, files)
        kept = _kept_cross(family, files)
        _family_test(family, entries, files, kept)
    except Refused as exc:
        plan.refused.append(str(exc))
        return plan
    files[LOADERS_FILE] = GEN.render(entries, dependencies)
    plan.files = files
    return plan


# --------------------------------------------------------------------------- formatting


def _first_party() -> list[str]:
    """The repository's first-party top-level names, as ruff finds them in the full tree.

    The formatting runs in a scratch copy holding only the planned files, where ruff would
    take an absent ``unifi_fabric.client`` for a third-party module and sort the imports
    differently from the repository's own run.
    """
    names = set()
    for base in (ROOT, ROOT / "src"):
        for child in base.iterdir():
            if (child / "__init__.py").is_file() or (child.suffix == ".py" and child.is_file()):
                names.add(child.stem)
    return sorted(names)


def _child_env(*, key: bool = True) -> dict[str, str]:
    """The environment of every process a move starts: no ambient server settings.

    Every ``UNIFI_*``/``MCP_*``/``FASTMCP_*`` variable is dropped, the moved tree (and the
    repository root, for ``tests``) comes first on ``PYTHONPATH``, and the API key is the
    placeholder (``key=False`` for a generator that refuses any ``UNIFI_*`` setting).
    """
    import os

    env = {k: v for k, v in os.environ.items() if not k.startswith(_SCRUBBED)}
    env["PYTHONPATH"] = os.pathsep.join((str(PKG.parent), str(ROOT)))
    if key:
        env["UNIFI_API_KEY"] = PROBE_KEY
    return env


def _ruff(paths: Sequence[Path], lost_code: set[Path]) -> None:
    ruff = [sys.executable, "-m", "ruff"]
    files = [str(p) for p in paths if p.suffix == ".py"]
    if not files:
        return
    lost = [str(p) for p in paths if p in lost_code and p.suffix == ".py"]
    if lost:
        subprocess.run(
            [*ruff, "check", "--fix", "--select", "F401", "-q", *lost],
            env=_child_env(key=False),
            check=False,
        )
    known = ", ".join(f'"{name}"' for name in _first_party())
    first_party = f"lint.isort.known-first-party = [{known}]"
    isort = [*ruff, "check", "--config", first_party, "--fix", "--select", "I", "-q"]
    subprocess.run([*isort, *files], env=_child_env(key=False), check=False)
    subprocess.run([*ruff, "format", "-q", *files], env=_child_env(key=False), check=True)


def _formatted(plan: Plan) -> dict[Path, str]:
    """The plan's files as ruff would leave them (in a scratch copy, nothing written)."""
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        shutil.copy(ROOT / "pyproject.toml", scratch / "pyproject.toml")
        mapping: dict[Path, Path] = {}
        for path, text in plan.files.items():
            dest = scratch / path.relative_to(ROOT)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
            mapping[path] = dest
        lost = {mapping[p] for p in plan.lost_code if p in mapping}
        cwd = Path.cwd()
        try:
            import os

            os.chdir(scratch)
            _ruff(list(mapping.values()), lost)
        finally:
            os.chdir(cwd)
        return {p: d.read_text(encoding="utf-8") for p, d in mapping.items()}


def move(family: str, check: bool, keep_cross_family: bool = False) -> int:
    plan = plan_family(family, keep_cross_family)
    if plan.refused:
        for note in dict.fromkeys(plan.notes):
            print(note)
        for reason in plan.refused:
            print(f"REFUSED (hand work): {reason}")
        return 1
    plan.files = _formatted(plan)
    _remap_na_proofs(plan)
    _follow_claim_sources(plan)
    _rewrite_doc_citations(plan)
    for note in dict.fromkeys(plan.notes):
        print(note)
    changed = plan.changed()
    for path in sorted(changed):
        print(("would write " if check else "wrote ") + str(path.relative_to(ROOT)))
    if check:
        if changed:
            print(f"{family}: {len(changed)} files would change")
            return 1
        print(f"{family}: moved; nothing to change")
        return 0
    if not changed:
        print(f"{family}: nothing to do")
        return 0
    snapshot = _snapshot(changed)
    try:
        for path, text in changed.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        _refresh_inventory()
        if ROUTE_SOURCES is not None and ROUTE_SOURCES.exists():
            subprocess.run(  # noqa: S603 - this interpreter and the repository's own writer
                [sys.executable, str(ROUTE_SOURCES), "--write"],
                cwd=ROOT,
                env=_child_env(),
                check=True,
            )
        _write_shapes_table()
        _check_route_sources()
        _smoke_import(changed)
        _undefined_names(changed)
        _smoke_calls(changed)
    except (OSError, subprocess.CalledProcessError, _SmokeFailed) as exc:
        _restore(snapshot)
        print(f"ROLLED BACK: {family}: {exc}; the tree is as it was before the move")
        return 1
    print(f"{family}: {len(changed)} files written")
    return 0


#: Where docs cite ``families/<f>/<module>.py::<name>`` (the skills and their plugin copies).
DOC_CITATION_ROOTS = ("skills", "plugins", "docs")
DOC_SUFFIXES = (".md", ".txt", ".json", ".yaml", ".yml")
_DOC_CITE = re.compile(
    r"((?:src/unifi_fabric/)?)(families/[a-z_]+/[a-z0-9_]+\.py)::([A-Za-z_][\w.]*)"
)


def _rewrite_doc_citations(plan: Plan) -> None:
    """Follow ``families/<f>/<module>.py::<name>`` citations in skills, plugins and docs.

    A name the module still defines stays. A tool wrapper of a moved step now lives in
    the family registrar; a moved helper in the file it moved to. Anything else that the
    module no longer defines is printed as a hand check. Runs on the formatted texts.
    """
    helpers = {(old, name): new for old, new, names in plan.moved_helpers for name in names}
    touched = {str(p.relative_to(PKG)) for p in plan.files if PKG in p.parents}
    for root in DOC_CITATION_ROOTS:
        base = ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in DOC_SUFFIXES or not path.is_file():
                continue
            text = plan.files.get(path, path.read_text(encoding="utf-8"))
            if "::" not in text:
                continue

            def repl(match: re.Match[str], path: Path = path) -> str:
                prefix, rel, qualname = match.groups()
                if rel not in touched:
                    return match.group(0)
                head = qualname.split(".", 1)[0]
                source = PKG / rel
                current = plan.files.get(source)
                if current is None and source.exists():
                    current = source.read_text(encoding="utf-8")
                defined = (
                    set()
                    if current is None
                    else {n for n, b in _bindings(ast.parse(current)).items() if b.kind == "def"}
                )
                if head in defined:
                    return match.group(0)
                family = rel.split("/")[1]
                if head in plan.moved_wrappers.get(rel, set()):
                    return f"{prefix}families/{family}/registrar.py::{qualname}"
                if (rel, head) in helpers:
                    return f"{prefix}{helpers[(rel, head)]}::{qualname}"
                plan.notes.append(f"hand check: {path.relative_to(ROOT)}: {match.group(0)}")
                return match.group(0)

            new = _DOC_CITE.sub(repl, text)
            if new != text:
                plan.files[path] = new
                plan.notes.append(f"doc citations: {path.relative_to(ROOT)} follows the move")


#: The acceptance harness's N/A proofs, where the repository has them (see ROUTE_SOURCES).
NA_PROOFS_NAME = "write_acceptance_na_proofs.py"
NA_PROOFS = next(iter(sorted(ROOT.glob(f"docs/*/{NA_PROOFS_NAME}"))), None)
_CITE_KEYS = (("cite", "literal"), ("base", "base_literal"), ("gate", "gate_literal"))


def _is_source(path: Path) -> bool:
    """A package source module the move wrote (not a test, and not the generated index)."""
    return path.suffix == ".py" and PKG in path.parents and path.name != "handlers.py"


def _line_map(before: list[str], after: list[str]) -> dict[int, int]:
    """1-based old line -> new line for every line a rewrite of a file kept."""
    matcher = difflib.SequenceMatcher(None, before, after, autojunk=False)
    out: dict[int, int] = {}
    for block in matcher.get_matching_blocks():
        for k in range(block.size):
            out[block.a + k + 1] = block.b + k + 1
    return out


def _remap_na_proofs(plan: Plan) -> None:
    """Follow the acceptance N/A proofs' ``file:line`` citations into the moved tree.

    Each proof cites a line and the literal that line must hold
    (``write_acceptance_na_proofs.verify``). A cited file the move changed is looked up
    by that literal: the line it now holds, in the same file or in a file the move wrote
    (a line the move kept maps through the unchanged lines, so a literal repeated in the
    file is told apart). One match rewrites the citation; none or several is printed as a
    hand check.
    """
    if NA_PROOFS is None or not NA_PROOFS.exists():
        return
    text = plan.files.get(NA_PROOFS, NA_PROOFS.read_text(encoding="utf-8"))
    proofs = None
    for node in ast.parse(text).body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and "NA_PROOFS" in _assigned_names(node):
            try:
                proofs = ast.literal_eval(node.value) if node.value is not None else None
            except ValueError:
                plan.notes.append("hand check: NA_PROOFS is not a literal; citations not followed")
                return
    if not isinstance(proofs, dict):
        return
    written = {
        str(p.relative_to(ROOT)): t.splitlines() for p, t in plan.files.items() if _is_source(p)
    }
    moved: dict[str, str] = {}
    for tool, proof in sorted(proofs.items()):
        for key, literal_key in _CITE_KEYS:
            cite, literal = proof.get(key), proof.get(literal_key)
            if not cite or not literal:
                continue
            rel, _, number = str(cite).rpartition(":")
            if rel not in written or not number.isdigit():
                continue
            lines = written[rel]
            line = int(number)
            if 0 < line <= len(lines) and literal in lines[line - 1]:
                continue
            # A line the move kept maps exactly (the module's unchanged lines, in order).
            before = (ROOT / rel).read_text(encoding="utf-8").splitlines()
            kept = _line_map(before, lines).get(line)
            old_line = before[line - 1].strip() if 0 < line <= len(before) else ""
            if kept is not None and literal in lines[kept - 1]:
                same = [kept]
            else:
                same = [i for i, text_line in enumerate(lines, 1) if literal in text_line]
            # A line the move took elsewhere (a constant to schemas.py or the common package)
            # is the same line there: match its whole text before the literal alone.
            exact = [
                (other, i)
                for other, other_lines in sorted(written.items())
                for i, text_line in enumerate(other_lines, 1)
                if old_line and literal in old_line and text_line.strip() == old_line
            ]
            if kept is None and len(exact) == 1:
                same, found = [], exact
            else:
                found = []
            found = (
                found
                or [(rel, i) for i in same]
                or [
                    (other, i)
                    for other, other_lines in sorted(written.items())
                    if other != rel
                    for i, text_line in enumerate(other_lines, 1)
                    if literal in text_line
                ]
            )
            if len(found) != 1:
                plan.notes.append(
                    f"hand check: NA proof {tool} {key} {cite}: {len(found)} lines hold {literal!r}"
                )
                continue
            new = f"{found[0][0]}:{found[0][1]}"
            if moved.setdefault(cite, new) != new:
                plan.notes.append(f"hand check: NA proof citation {cite} moves to two places")
    if not moved:
        return
    for old, new in moved.items():
        text = text.replace(f'"{old}"', f'"{new}"')
    plan.files[NA_PROOFS] = text
    plan.notes.append(f"NA proofs: {len(moved)} citations followed the move")


#: The documentation claim ledger: each manual claim names a ``source`` file that must hold
#: its ``source_find`` text (``scripts/docs_claim_ledger.py``).
CLAIMS = ROOT / "scripts" / "docs_claim_ledger_manual.json"


def _follow_claim_sources(plan: Plan) -> None:
    """A manual claim whose source text moved names the file it moved to.

    A claim's ``source`` the move changed that no longer holds its ``source_find`` text is
    looked up in the files the move wrote: one holding it re-points the claim; none or
    several is printed as a hand check.
    """
    if not CLAIMS.exists():
        return
    import json

    text = plan.files.get(CLAIMS, CLAIMS.read_text(encoding="utf-8"))
    claims = json.loads(text)
    written = {str(p.relative_to(ROOT)): t for p, t in plan.files.items() if _is_source(p)}
    changed = False
    for claim in claims if isinstance(claims, list) else []:
        source, find = claim.get("source"), claim.get("source_find")
        if source not in written or not find or find in written[source]:
            continue
        found = sorted(rel for rel, body in written.items() if find in body)
        if len(found) != 1:
            plan.notes.append(
                f"hand check: claim {claim.get('claim_id')}: {source} no longer holds "
                f"{find!r} ({len(found)} written files do)"
            )
            continue
        anchor = text.find(f'"claim_id": "{claim.get("claim_id")}"')
        at = text.find(f'"source": "{source}"', anchor)
        if anchor < 0 or at < 0:
            plan.notes.append(f"hand check: claim {claim.get('claim_id')}: source not found")
            continue
        text = text[:at] + f'"source": "{found[0]}"' + text[at + len(f'"source": "{source}"') :]
        changed = True
        plan.notes.append(f"claim ledger: {claim.get('claim_id')} -> {found[0]}")
    if changed:
        plan.files[CLAIMS] = text


class _SmokeFailed(Exception):
    """The moved tree does not import."""


def _snapshot(changed: dict[Path, str]) -> dict[Path, bytes | None]:
    """Every file the move or the route-source writer may touch, as it is (None: absent)."""
    paths = set(changed)
    if ROUTE_SOURCES is not None and ROUTE_SOURCES.exists():
        paths |= {p for p in ROUTE_SOURCES.parent.glob("*.py")}
    if SHAPES_GEN.exists():
        paths.add(SHAPES_TABLE)
    if MEMBERSHIP_GEN.exists():
        paths.add(MEMBERSHIP)
    if DEFERRED_GEN.exists():
        paths.add(DEFERRED)
    return {p: (p.read_bytes() if p.exists() else None) for p in sorted(paths)}


def _member_pairs(text: str) -> list[tuple[str, str]]:
    """``(tool, family)`` of each ``Member(name, family, step)`` line of the inventory."""
    out = []
    for node in ast.walk(ast.parse(text)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Member"
            and len(node.args) == 3
        ):
            values = [a.value for a in node.args if isinstance(a, ast.Constant)]
            if len(values) == 3:
                out.append((str(values[0]), str(values[1])))
    return sorted(out)


def _generator(script: Path, what: str) -> None:
    done = subprocess.run(  # noqa: S603 - this interpreter and the repository's own generator
        [sys.executable, str(script), "--generate"],
        cwd=ROOT,
        env=_child_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        lines = (done.stdout + done.stderr).strip().splitlines() or ["(no output)"]
        raise _SmokeFailed(f"{what} does not regenerate: {lines[0][:300]}")


def _refresh_inventory() -> None:
    """Refresh the explicit inventory's steps; its ``(tool, family)`` pairs must not change.

    The server refuses to start when a member names a step the loader map no longer has,
    so a move refreshes ``MEMBERS`` (``gen_membership.py --generate``). Families are
    authored there, never inferred: a move changes steps and order only, and any change to
    a ``(tool, family)`` pair fails the move. ``deferred.json`` follows the refreshed steps.
    """
    if not (MEMBERSHIP_GEN.exists() and MEMBERSHIP.exists()):
        return
    before = _member_pairs(MEMBERSHIP.read_text(encoding="utf-8"))
    _generator(MEMBERSHIP_GEN, "the explicit inventory (gen_membership.py)")
    after = _member_pairs(MEMBERSHIP.read_text(encoding="utf-8"))
    if before != after:
        changed = sorted(set(before) ^ set(after))
        raise _SmokeFailed(
            f"the explicit inventory's (tool, family) pairs changed: {changed[:5]}"
            + (f" (and {len(changed) - 5} more)" if len(changed) > 5 else "")
        )
    print(f"explicit inventory: steps refreshed; {len(after)} (tool, family) pairs unchanged")
    if DEFERRED_GEN.exists():
        _generator(DEFERRED_GEN, "the lazy-loading snapshot (gen_deferred_catalog.py)")
        print(f"lazy-loading snapshot regenerated: {DEFERRED.relative_to(ROOT)}")


#: Runs the shape generator's ``--write`` with every tool's function loaded: under deferred
#: loading (public #41) the server registers stubs until a step loads, and the generator
#: reads each registered tool's function (the test suite's conftest loads them the same way).
_SHAPES_RUN = """
import importlib.util, runpy, sys
if importlib.util.find_spec("unifi_fabric.catalog.deferred") is not None:
    from unifi_fabric import server
    from unifi_fabric.catalog import deferred
    deferred.load_all(server.mcp)
sys.argv = ["tool_shapes_gen", "--write"]
runpy.run_module("tests.tool_shapes_gen", run_name="__main__")
"""


def _write_shapes_table() -> None:
    """Regenerate the tool-shape table: it records each shape class's module (``schemas``)."""
    if not SHAPES_GEN.exists():
        return
    done = subprocess.run(  # noqa: S603 - this interpreter and the repository's own generator
        [sys.executable, "-c", _SHAPES_RUN],
        cwd=ROOT,
        env=_child_env(key=False),  # it refuses any ambient server setting (a partial catalog)
        capture_output=True,  # it prints its whole inventory
        text=True,
        check=False,
    )
    if done.returncode:
        last = (done.stderr.strip().splitlines() or ["(no output)"])[-1]
        raise _SmokeFailed(f"the tool-shape table does not regenerate: {last}")
    # The generator writes repr text; the committed table is ruff-formatted.
    subprocess.run(  # noqa: S603 - this interpreter, ruff on the generated table
        [sys.executable, "-m", "ruff", "format", "-q", str(SHAPES_TABLE)],
        cwd=ROOT,
        env=_child_env(key=False),
        check=True,
    )
    print(f"tool-shape table regenerated: {SHAPES_TABLE.relative_to(ROOT)}")


def _check_route_sources() -> None:
    """The route citations as written must pass the writer's own ``--check`` (no drift)."""
    if ROUTE_SOURCES is None or not ROUTE_SOURCES.exists():
        return
    done = subprocess.run(  # noqa: S603 - this interpreter and the repository's own check
        [sys.executable, str(ROUTE_SOURCES), "--check"],
        cwd=ROOT,
        env=_child_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        lines = (done.stdout + done.stderr).strip().splitlines() or ["(no output)"]
        raise _SmokeFailed(f"the route citations drift after the move: {lines[-1][:300]}")
    print("route citations: --check passes")


def _restore(snapshot: dict[Path, bytes | None]) -> None:
    for path, data in snapshot.items():
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(data)


def _smoke_import(changed: dict[Path, str]) -> None:
    """Import the server (or, without one, every written module) in a fresh process."""
    if (PKG / "server.py").exists():
        modules = ["unifi_fabric.server"]
    else:
        modules = sorted(
            ".".join(p.relative_to(PKG.parent).with_suffix("").parts)
            for p in changed
            if p.suffix == ".py" and PKG in p.parents and p.name != "__init__.py"
        )
    code = (
        f"import importlib, sys\nsys.path.insert(0, {str(PKG.parent)!r})\n"
        f"for name in {modules!r}:\n    importlib.import_module(name)\n"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed import probe
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=_child_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        last = (done.stderr.strip().splitlines() or ["(no output)"])[-1]
        raise _SmokeFailed(f"the moved tree does not import: {last}")


def _undefined_names(changed: dict[Path, str]) -> None:
    """ruff F821 on every written module: a moved name must not read an undefined one."""
    files = [str(p) for p in changed if p.suffix == ".py" and p.exists()]
    if not files:
        return
    done = subprocess.run(  # noqa: S603 - this interpreter, ruff on the written files
        [sys.executable, "-m", "ruff", "check", "--select", "F821", "--no-cache", "-q", *files],
        cwd=ROOT,
        env=_child_env(key=False),
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        first = (done.stdout.strip().splitlines() or ["(no output)"])[0]
        raise _SmokeFailed(f"undefined name after the move: {first}")


#: The one-call probe: each touched family's first tool with a required argument is
#: called with none, in process, through the server's own session (its middleware: the
#: write-policy and area checks run on every call). A validation error is the expected
#: answer; an internal error fails the move. No request leaves the process.
_CALL_PROBE = """
import asyncio, inspect, json, sys
from fastmcp import Client, FastMCP
from unifi_fabric import server

FAMILIES = json.loads(sys.argv[1])
try:  # the explicit inventory (public #42 step 6): a tool's family without loading it
    from unifi_fabric.catalog.membership import family_index
    FAMILY = family_index()
except ImportError:
    FAMILY = None


def in_family(name, tool, family):
    # Under deferred loading a registered tool is a stub until its step loads (no fn).
    if FAMILY is not None:
        return FAMILY.get(name) == family
    return inspect.unwrap(tool.fn).__module__.startswith(f"unifi_fabric.families.{family}.")


async def main():
    if not isinstance(getattr(server, "mcp", None), FastMCP):
        return 0
    registered = {t.name: t for t in await server.mcp.list_tools(run_middleware=False)}
    async with Client(server.mcp) as client:
        listed = {t.name: t for t in await client.list_tools()}
        for family in FAMILIES:
            mine = sorted(
                n
                for n, t in registered.items()
                if n in listed
                and in_family(n, t, family)
                and (listed[n].inputSchema or {}).get("required")
            )
            reads = [n for n in mine if getattr(listed[n].annotations, "readOnlyHint", False)]
            if not mine:
                continue
            name = (reads or mine)[0]
            result = await client.call_tool(name, {}, raise_on_error=False)
            text = " ".join(getattr(c, "text", "") for c in result.content)
            if "Internal server error" in text or "Traceback" in text:
                print(f"{family}: {name}: {text[:200]}")
                return 1
    return 0


raise SystemExit(asyncio.run(main()))
"""


def _smoke_calls(changed: dict[Path, str]) -> None:
    """One in-process tools/call per family the move touched (see :data:`_CALL_PROBE`)."""
    if not (PKG / "server.py").exists():
        return
    families = sorted(
        {p.parent.name for p in changed if p.suffix == ".py" and p.parent.parent == FAMILIES}
    )
    if not families:
        return
    import json

    # Always the placeholder key, never the caller's: the server needs one to start, and
    # every probe call fails argument validation before any request is made. No ambient
    # UNIFI_*/MCP_*/FASTMCP_* (a family filter would hide a family: a silent pass).
    env = _child_env()
    env["UNIFI_TOOL_MODE"] = "full"
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed in-process probe
        [sys.executable, "-c", _CALL_PROBE, json.dumps(families)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        lines = (done.stdout + done.stderr).strip().splitlines() or ["(no output)"]
        raise _SmokeFailed(f"a tool call fails after the move: {lines[-1][:300]}")


def report() -> int:
    """Every family's move plan (the fan-out table), without writing anything."""
    sys.path.insert(0, str(PKG.parent))
    entries, _deps = _loaders()
    from unifi_fabric.catalog import load_catalog

    counts: dict[str, int] = {}
    for spec in load_catalog().by_name().values():
        counts[spec.family] = counts.get(spec.family, 0) + 1
    cross = family_imports()
    print("| family | tools | steps | modules | cross-family imports (importer -> family) | plan |")
    print("| --- | ---: | ---: | --- | --- | --- |")
    for family in GEN.family_dirs():
        own = [e for e in entries if e.family == family]
        modules = sorted({e.module for e in own})
        imports = [
            f"{f.split('/', 2)[2]}:{line}->{o}" for f, line, o in cross if f.split("/")[1] == family
        ]
        plan = plan_family(family)
        state = ""
        if plan.refused:
            state = "cross-family HAND WORK: " + "; ".join(plan.refused) + "; "
            plan = plan_family(family, keep_cross_family=True)
            if plan.refused:
                state += "layout refused too: " + "; ".join(plan.refused)
        if not plan.refused:
            plan.files = _formatted(plan)
            changed = len(plan.changed())
            flag = " --keep-cross-family" if state else ""
            state += f"move{flag}: {changed} files" if changed else "moved"
        print(
            f"| {family} | {counts.get(family, 0)} | {len(own)} | {', '.join(modules)} | "
            f"{', '.join(imports) or 'none'} | {state} |"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    # The loader map is imported and then rewritten in the same run, often within the
    # same second and at the same size (``alpha_mod`` -> ``registrar``): never leave a
    # .pyc that a later import would take as current.
    sys.dont_write_bytecode = True
    import os

    # The move reads the package in this process too: no ambient server setting steers it.
    for name in [k for k in os.environ if k.startswith(_SCRUBBED)]:
        del os.environ[name]
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--family", help="the family directory to move")
    parser.add_argument("--check", action="store_true", help="dry run: exit 1 if it would change")
    parser.add_argument("--report", action="store_true", help="every family's plan")
    parser.add_argument(
        "--keep-cross-family",
        action="store_true",
        help="move the layout but leave F's imports of other families (listed; hand work)",
    )
    args = parser.parse_args(argv)
    if args.report:
        return report()
    if not args.family:
        parser.error("--family is required (or --report)")
    return move(args.family, args.check, args.keep_cross_family)


if __name__ == "__main__":
    raise SystemExit(main())
