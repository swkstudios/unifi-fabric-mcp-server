#!/usr/bin/env python3
"""Generate and check the explicit family loader map, ``src/unifi_fabric/catalog/loaders.py``.

The loader map is the one registration path of the server (public #42): every
registration step, in registration order, which is the ``tools/list`` order
(``scripts/codemod_move_wrappers.py``). It is committed, never derived at runtime.

``--generate --server-ref REF`` wrote it once, from the ``register`` calls of
``src/unifi_fabric/server.py`` at the git ref ``REF`` (each step with its ``deps_fn``
form, and its module stem as the step's ``origin``), with the family dependencies the
inventory scanned until then as the declared ones. Since that commit the file is the
source: a family move edits its own entries (``module``/``function``) and keeps each
``origin``, so no tool's ``MODULE_INDEX`` stem changes.

``--check`` (the default) compares the committed map with the family directories,
reading their source only (no family module is imported):

* every entry names an existing family directory, a module file in it and a top-level
  ``register`` / ``register_<n>`` function of that module, with a known ``deps`` form;
* no entry is listed twice, and no module key
  (:func:`unifi_fabric.catalog.loaders.module_key`) names two files;
* every ``register`` / ``register_<n>`` function of every non-private module in a family
  directory is an entry (none unregistered);
* each ``origin`` is a module stem (an index key only; it may span directories);
* the declared dependencies are keyed by the catalog families and name only other known
  families, sorted;
* the file is exactly what this script renders from its entries.

Exit status: 0 clean, 1 a difference (each one printed), 2 a usage error.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

PKG = ROOT / "src" / "unifi_fabric"
FAMILIES = PKG / "families"
TARGET = PKG / "catalog" / "loaders.py"
SERVER_REL = "src/unifi_fabric/server.py"
_REGISTER_RE = re.compile(r"register(?:_[0-9]+)?")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_FAMILY_PACKAGE = "unifi_fabric.families."
DEPS_FORMS = ("late", "bound")

HEADER = '''"""The explicit family loader map (public #42): every registration step, in order.

GENERATED once by ``scripts/gen_loaders.py --generate`` from the ``register`` calls of
``server.py``; committed since then, and never derived at runtime. A family move edits
only its own entries (``module`` and ``function``) and keeps each ``origin``.
``python scripts/gen_loaders.py --check`` compares this file with the family directories.

:data:`LOADERS` is the one registration path of every profile: the server runs
:func:`load` once, so the registration order (the ``tools/list`` order) is the order of
the entries. Family selection removes tools afterwards (:mod:`unifi_fabric.policy`); it
never takes a different path. Each entry names:

* ``family``: the family directory under ``unifi_fabric/families/``;
* ``module``, ``function``: the module in that directory and its ``register`` /
  ``register_<n>`` function, called as ``function(mcp, deps_fn)``;
* ``deps``: the ``deps_fn`` it is given: ``late`` is ``lambda: server._require()``, read
  at call time, so a patched ``server._require`` applies; ``bound`` is
  ``server._require`` itself. Each step keeps the form it was registered with;
* ``origin``: the tools module stem its tools are indexed under (``MODULE_INDEX``, which
  keys the discovery search vocabulary). It is an index key only: a family move or a
  split step keeps it, so one origin may span family directories, and it never decides a
  family (the step's ``family`` directory does). While the origin's module exists,
  ``server.<origin>`` stays bound to it.

:data:`FAMILY_DEPENDENCIES` declares, per catalog family, the other families its steps'
modules depend on (``FamilySpec.dependencies``).
"""

from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Callable, Mapping
from types import ModuleType
from typing import Any, Literal, NamedTuple

#: The package of the family directories.
FAMILIES_PACKAGE = "unifi_fabric.families"

#: The common package: code that two or more families use lives here, outside every
#: family directory, so a family's modules never need another family's (public #41: a
#: disabled family is never imported). A helper only one family uses stays in that family
#: as a private ``_*.py`` module. No loader entry names this package.
COMMON_PACKAGE = "unifi_fabric.shared_shapes"

#: Module stems of the family-owned layout (public #42): any family may have each one, so
#: their module key is qualified by the family (:func:`module_key`).
LAYOUT_STEMS: tuple[str, ...] = ("handlers", "schemas", "registrar")


def module_key(family: str, module: str) -> str:
    """The key of a family module: its stem, or ``<family>/<stem>`` for a layout stem."""
    return f"{family}/{module}" if module in LAYOUT_STEMS else module


class Loader(NamedTuple):
    """One registration step of the loader map."""

    family: str
    module: str
    function: str
    deps: Literal["late", "bound"]
    origin: str

    @property
    def module_path(self) -> str:
        """The dotted module path."""
        return f"{FAMILIES_PACKAGE}.{self.family}.{self.module}"

    @property
    def ref(self) -> str:
        """``<module path>:<function>``, the form of ``FamilySpec.loader``."""
        return f"{self.module_path}:{self.function}"

    @property
    def key(self) -> str:
        """The module key (:func:`module_key`)."""
        return module_key(self.family, self.module)
'''

FOOTER = '''

def refs() -> tuple[str, ...]:
    """Every step's ``<module path>:<function>``, in order."""
    return tuple(entry.ref for entry in LOADERS)


def origin_module(entry: Loader) -> ModuleType | None:
    """The module named by ``entry.origin``, while it exists, else None.

    Looked for in the step's own directory first, then in the other family directories
    of the map, in map order (an origin may span directories); a found module is
    imported. Module stems outside the layout are unique across families
    (``gen_loaders.py --check``), so at most one directory has it.
    """
    for family in dict.fromkeys((entry.family, *(e.family for e in LOADERS))):
        name = f"{FAMILIES_PACKAGE}.{family}.{entry.origin}"
        if importlib.util.find_spec(name) is not None:
            return importlib.import_module(name)
    return None


def load(mcp: Any, *, late: Callable[[], Any], bound: Callable[[], Any]) -> dict[str, Any]:
    """Run every step in order and return the server's names for them.

    The names are each step's returned wrappers by tool name (the ``server.<tool>``
    re-exports), each non-layout module of the map by stem (``server.<module>``), and each
    step's origin module while it exists (``server.<origin>``, so moving a step out of a
    module keeps that attribute). A name bound to two different objects fails.
    """
    names: dict[str, Any] = {}

    def add(name: str, value: Any) -> None:
        if names.setdefault(name, value) is not value:
            raise RuntimeError(f"loader map: the name {name!r} is given twice")

    for entry in LOADERS:
        module = importlib.import_module(entry.module_path)
        if entry.module not in LAYOUT_STEMS:
            add(entry.module, module)
        if entry.origin != entry.module or entry.module in LAYOUT_STEMS:
            origin = origin_module(entry)
            if origin is not None:
                add(entry.origin, origin)
        returned = getattr(module, entry.function)(mcp, late if entry.deps == "late" else bound)
        for name, wrapper in (returned or {}).items():
            add(name, wrapper)
    return names
'''


class Entry(NamedTuple):
    """A loader entry as this script reads and renders it."""

    family: str
    module: str
    function: str
    deps: str
    origin: str


def _q(value: str) -> str:
    return '"' + value + '"'


def render(entries: Sequence[Any], dependencies: Mapping[str, Sequence[str]]) -> str:
    """The loader map file for ``entries`` and the declared dependencies."""
    lines = [
        HEADER.rstrip("\n"),
        "",
        "",
        "#: The registration steps, in registration (``tools/list``) order.",
        "LOADERS: tuple[Loader, ...] = (",
    ]
    for entry in entries:
        lines += [
            "    Loader(",
            f"        family={_q(entry.family)},",
            f"        module={_q(entry.module)},",
            f"        function={_q(entry.function)},",
            f"        deps={_q(entry.deps)},",
            f"        origin={_q(entry.origin)},",
            "    ),",
        ]
    lines += [
        ")",
        "",
        "#: The other families each catalog family's steps depend on (declared, sorted).",
        "FAMILY_DEPENDENCIES: Mapping[str, tuple[str, ...]] = {",
    ]
    for family, deps in dependencies.items():
        inner = ", ".join(_q(d) for d in deps)
        value = f"({inner},)" if len(deps) == 1 else f"({inner})"
        lines.append(f"    {_q(family)}: {value},")
    lines.append("}")
    return "\n".join(lines) + "\n" + FOOTER


# --------------------------------------------------------------------------- generation


def server_calls(source: str) -> list[Entry]:
    """The loader entries of server.py's register calls, in order."""
    tree = ast.parse(source)
    imported: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            parts = node.module.split(".")
            if len(parts) == 2 and parts[0] == "families":
                for alias in node.names:
                    imported[alias.asname or alias.name] = (parts[1], alias.name)
    entries: list[Entry] = []
    for node in tree.body:
        value = node.value if isinstance(node, (ast.Assign, ast.Expr)) else None
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)):
            continue
        target = value.func.value
        if not (isinstance(target, ast.Name) and target.id in imported):
            continue
        if not _REGISTER_RE.fullmatch(value.func.attr):
            continue
        deps_arg = value.args[1]
        if isinstance(deps_arg, ast.Lambda):
            deps = "late"
        elif isinstance(deps_arg, ast.Name) and deps_arg.id == "_require":
            deps = "bound"
        else:
            raise SystemExit(f"server.py line {node.lineno}: unknown deps_fn form")
        family, module = imported[target.id]
        entries.append(Entry(family, module, value.func.attr, deps, module))
    return entries


def _module_family_dirs(module: ModuleType) -> set[str]:
    """The family packages ``module`` lives in or imports directly (the pre-map scan)."""

    def family_dir(name: str) -> str | None:
        if not name.startswith(_FAMILY_PACKAGE):
            return None
        return name[len(_FAMILY_PACKAGE) :].split(".", 1)[0]

    found = {d for d in (family_dir(module.__name__),) if d}
    for value in vars(module).values():
        source = value.__name__ if isinstance(value, ModuleType) else None
        if source is None:
            source = getattr(value, "__module__", None)
        if isinstance(source, str):
            directory = family_dir(source)
            if directory:
                found.add(directory)
    return found


def scanned_dependencies() -> dict[str, tuple[str, ...]]:
    """Each catalog family's dependencies as the inventory scanned them before the map."""
    from unifi_fabric.catalog import META_FAMILY, load_catalog
    from unifi_fabric.catalog.inventory import loader_ref, runtime_view
    from unifi_fabric.families import ALL_FAMILIES

    view = asyncio.run(runtime_view())
    catalog = load_catalog().by_name()
    families = [*ALL_FAMILIES, META_FAMILY]
    steps: dict[str, list[str]] = {family: [] for family in families}
    for listed in view.listed:
        name = listed["name"]
        steps[catalog[name].family].append(loader_ref(view.tools[name].fn))
    out: dict[str, tuple[str, ...]] = {}
    for family in families:
        dirs: set[str] = set()
        for ref in dict.fromkeys(steps[family]):
            module = sys.modules.get(ref.split(":", 1)[0])
            if module is not None:
                dirs |= _module_family_dirs(module)
        out[family] = tuple(sorted(d for d in dirs if d in families and d != family))
    return out


def generate(server_ref: str) -> str:
    """The loader map from server.py at ``server_ref`` and the scanned dependencies."""
    source = subprocess.run(
        ["git", "show", f"{server_ref}:{SERVER_REL}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return render(server_calls(source), scanned_dependencies())


# --------------------------------------------------------------------------- check


def _top_level_registers(path: Path) -> list[str]:
    return [
        node.name
        for node in ast.parse(path.read_text()).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _REGISTER_RE.fullmatch(node.name)
    ]


def family_dirs(families: Path = FAMILIES) -> list[str]:
    """The family directories (packages) under ``families``."""
    return sorted(p.name for p in families.iterdir() if (p / "__init__.py").is_file())


def check(
    entries: Sequence[Any],
    dependencies: Mapping[str, Sequence[str]],
    text: str,
    *,
    families: Path = FAMILIES,
    known_families: Iterable[str] | None = None,
) -> list[str]:
    """Every difference between the loader map and the family directories."""
    problems: list[str] = []
    dirs = set(family_dirs(families))
    seen: set[tuple[str, str, str]] = set()
    key_path: dict[str, str] = {}
    for index, entry in enumerate(entries):
        where = f"entry {index} ({entry.family}/{entry.module}:{entry.function})"
        triple = (entry.family, entry.module, entry.function)
        if triple in seen:
            problems.append(f"duplicate entry: {where}")
        seen.add(triple)
        if entry.family not in dirs:
            problems.append(f"stale entry: {where}: no family directory {entry.family!r}")
            continue
        path = families / entry.family / f"{entry.module}.py"
        if entry.module.startswith("_") or not path.is_file():
            problems.append(f"stale entry: {where}: no module file {entry.family}/{path.name}")
            continue
        if not _REGISTER_RE.fullmatch(entry.function):
            problems.append(f"invalid entry: {where}: not a register or register_<n> function")
        elif entry.function not in _top_level_registers(path):
            problems.append(f"stale entry: {where}: the module has no top-level {entry.function}")
        if entry.deps not in DEPS_FORMS:
            problems.append(f"invalid entry: {where}: deps {entry.deps!r} is not late or bound")
        if not _NAME_RE.fullmatch(entry.origin):
            problems.append(f"invalid entry: {where}: origin {entry.origin!r} is not a stem")
        key = _module_key(entry.family, entry.module)
        rel = f"{entry.family}/{entry.module}.py"
        if key_path.setdefault(key, rel) != rel:
            problems.append(f"module key collision: {key!r} names {key_path[key]} and {rel}")
    for family in sorted(dirs):
        for path in sorted((families / family).glob("*.py")):
            if path.stem.startswith("_"):
                continue
            for function in _top_level_registers(path):
                if (family, path.stem, function) not in seen:
                    problems.append(
                        f"missing entry: families/{family}/{path.name}:{function} registers "
                        "tools but is not in the loader map"
                    )
    if known_families is not None:
        known = list(known_families)
        if list(dependencies) != known:
            problems.append(
                f"FAMILY_DEPENDENCIES keys {list(dependencies)} are not the families {known}"
            )
        for family, deps in dependencies.items():
            if any(d not in known or d == family for d in deps) or list(deps) != sorted(set(deps)):
                problems.append(
                    f"FAMILY_DEPENDENCIES[{family!r}] {list(deps)} is not a sorted list of "
                    "other known families"
                )
    if text != render(entries, dependencies):
        problems.append("catalog/loaders.py is not what scripts/gen_loaders.py renders")
    return problems


def _module_key(family: str, module: str) -> str:
    from unifi_fabric.catalog.loaders import module_key

    return module_key(family, module)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="compare with the directories")
    parser.add_argument("--generate", action="store_true", help="write the map (done once)")
    parser.add_argument("--server-ref", help="git ref of the server.py to generate from")
    args = parser.parse_args(argv)
    if args.generate:
        if not args.server_ref:
            parser.error("--generate needs --server-ref")
        TARGET.write_text(generate(args.server_ref))
        print(f"wrote {TARGET.relative_to(ROOT)}")
        return 0
    from unifi_fabric.catalog import META_FAMILY
    from unifi_fabric.catalog.loaders import FAMILY_DEPENDENCIES, LOADERS
    from unifi_fabric.families import ALL_FAMILIES

    problems = check(
        LOADERS,
        FAMILY_DEPENDENCIES,
        TARGET.read_text(),
        known_families=[*ALL_FAMILIES, META_FAMILY],
    )
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print(
        f"loader map: {len(LOADERS)} steps, {len({e.key for e in LOADERS})} modules in "
        f"{len(family_dirs())} family directories; matches the directories"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
