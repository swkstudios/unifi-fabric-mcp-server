#!/usr/bin/env python3
"""Move server.py's inline ``@mcp.tool`` wrappers into the tools/ module they delegate to.

Usage:
    python scripts/codemod_move_wrappers.py [--modules protect,connector,...] [--check]

Each contiguous run of inline wrappers that delegate to one tools/ module (the module
``families`` classifies them by, the first ``<module>.<attr>`` reference in the body)
becomes a ``register`` function in that module (``register``, ``register_2``, ... when a
module has several runs). The wrappers are nested inside it unchanged apart from their
indentation and ``_require()`` -> ``deps_fn()``. In server.py the run is replaced, at the
same position, by the call to that function and one re-export per wrapper, so the
registration order (and therefore the tools/list order) and ``server.<wrapper>``
attribute access stay as they were. ``deps_fn`` is ``lambda: _require()`` so a patched
``server._require`` still applies.

The server-only helpers the wrappers use move to ``tools/_shared.py``
(``_image_result``, ``_nullable_default``, ``_validate_optional_site``) with a
``get_settings`` that forwards to ``server.get_settings`` at call time, so the settings
cache and its test patches stay in server.py; server.py imports the moved helpers back.

The codemod is deterministic and re-runnable: a module whose runs are already moved is
left alone; ``--check`` exits 1 when a run would still move. Touched files are
formatted with ``ruff format`` and import-sorted with ``ruff check --fix --select I``.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import subprocess
import sys
import tokenize
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "unifi_fabric"
SERVER = PKG / "server.py"
TOOLS = PKG / "tools"
SHARED = TOOLS / "_shared.py"

#: server.py helpers moved verbatim to tools/_shared.py.
MOVED_HELPERS: tuple[str, ...] = ("_image_result", "_nullable_default", "_validate_optional_site")
#: server.py names the wrappers reach through tools/_shared.py without moving them.
FORWARDED: dict[str, str] = {
    "get_settings": (
        "def get_settings() -> Settings:\n"
        '    """The server\'s lazily built settings (``server.get_settings``, read per call)."""\n'
        "    from .. import server\n"
        "\n"
        "    return server.get_settings()\n"
    ),
}
SHARED_HEADER = (
    '"""Server-only helpers shared by the tool wrappers moved out of server.py.\n'
    "\n"
    "``get_settings`` forwards to :func:`unifi_fabric.server.get_settings` at call time, so the\n"
    "settings cache (and any test patch of it) stays in server.py.\n"
    '"""\n'
    "\n"
    "from __future__ import annotations\n"
)


def _is_tool(node: ast.stmt) -> bool:
    if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
        return False
    for dec in node.decorator_list:
        func = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(func, ast.Attribute) and func.attr == "tool":
            return True
    return False


def _tool_modules() -> set[str]:
    sys.path.insert(0, str(PKG.parent))
    from unifi_fabric.families import MODULE_FAMILY

    return set(MODULE_FAMILY)


def _delegate(node: ast.AST, modules: set[str]) -> str | None:
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Attribute)
            and isinstance(child.value, ast.Name)
            and child.value.id in modules
        ):
            return child.value.id
    return None


def _start(node: ast.stmt) -> int:
    decorators = getattr(node, "decorator_list", [])
    return min([node.lineno, *(d.lineno for d in decorators)])


def _free_names(nodes: list[ast.stmt]) -> list[str]:
    """Names the nodes load that they do not bind themselves (builtins excluded)."""
    out: list[str] = []
    for node in nodes:
        bound: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.arg):
                bound.add(child.arg)
            elif isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                bound.add(child.id)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                bound.add(child.name)
            elif isinstance(child, ast.ExceptHandler) and child.name:
                bound.add(child.name)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    bound.add(alias.asname or alias.name.split(".")[0])
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Load)
                and child.id not in bound
                and not hasattr(builtins, child.id)
                and child.id not in out
            ):
                out.append(child.id)
    return out


def _server_imports(tree: ast.Module) -> dict[str, tuple[str, str, str | None, int]]:
    """``local name -> (kind, module, imported name, level)`` for server.py's top imports."""
    out: dict[str, tuple[str, str, str | None, int]] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                out[local] = ("import", alias.name, alias.asname, 0)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                out[alias.asname or alias.name] = (
                    "from",
                    node.module or "",
                    alias.name if alias.asname is None else f"{alias.name} as {alias.asname}",
                    node.level,
                )
    return out


def _import_line(spec: tuple[str, str, str | None, int], target: str) -> str:
    """Rewrite one server.py import for a module in tools/ (``target`` is its stem)."""
    kind, module, name, level = spec
    if kind == "import":
        return f"import {module}" + (f" as {name}" if name else "")
    if name is None:
        raise SystemExit(f"malformed server.py import of {module}")
    if level == 0:
        return f"from {module} import {name}"
    if level != 1:
        raise SystemExit(f"unexpected relative import level {level} in server.py")
    if module == "tools":
        return f"from . import {name}"
    if module.startswith("tools."):
        return f"from .{module.removeprefix('tools.')} import {name}"
    return f"from ..{module} import {name}" if module else f"from .. import {name}"


def _top_bindings(tree: ast.Module) -> dict[str, str]:
    """``name -> source text of the binding statement`` for a module's top level."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                if isinstance(node, ast.ImportFrom):
                    dots = "." * node.level
                    out[local] = f"from {dots}{node.module or ''} import {alias.name}"
                else:
                    out[local] = f"import {alias.name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = f"def {node.name}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name):
                        out[child.id] = f"assign {child.id}"
        elif isinstance(node, ast.If):
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    for alias in child.names:
                        out.setdefault(alias.asname or alias.name.split(".")[0], "if-import")
    return out


def _normalise_from(line: str) -> str:
    """``from X import a as b`` -> ``from X import a`` (for binding comparison)."""
    return line.split(" as ", 1)[0]


def _needed_imports(
    names: list[str],
    server_imports: dict[str, tuple[str, str, str | None, int]],
    target_tree: ast.Module,
    target: str,
    via_shared: set[str],
) -> list[str]:
    """Import lines ``target`` needs for ``names``; fails on a conflicting binding."""
    have = _top_bindings(target_tree)
    lines: list[str] = []
    for name in names:
        if name in {"mcp", "_require"}:
            continue
        if name in via_shared:
            line = f"from ._shared import {name}"
            want = f"from ._shared import {name}"
        elif name in server_imports:
            line = _import_line(server_imports[name], target)
            want = _normalise_from(line)
        else:
            raise SystemExit(f"{target}: wrapper name {name!r} has no server.py import to carry")
        if name in have:
            current = have[name]
            same = current == want or (
                # ``from . import protect`` in tools/ binds the same module either way.
                current.startswith("from .") and _normalise_from(current) == want
            )
            if not same:
                raise SystemExit(
                    f"{target}: {name!r} is already bound as {current!r}, needs {want!r}"
                )
            continue
        lines.append(line)
    return lines


def _string_interiors(source: str, first: int, last: int) -> set[int]:
    """Line numbers (1-based) inside a multi-line non-docstring string in [first, last]."""
    tree = ast.parse(source)
    docstrings: set[tuple[int, int]] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    docstrings.add((body[0].value.lineno, body[0].value.col_offset))
    lines: set[int] = set()
    fstart = getattr(tokenize, "FSTRING_START", -1)
    fend = getattr(tokenize, "FSTRING_END", -1)
    open_f: list[tuple[int, int]] = []
    for tok in tokenize.generate_tokens(StringIO(source).readline):
        if tok.type == fstart:
            open_f.append(tok.start)
            continue
        if tok.type == fend:
            (srow, scol), erow = open_f.pop(), tok.end[0]
        elif tok.type == tokenize.STRING:
            (srow, scol), erow = tok.start, tok.end[0]
        else:
            continue
        if erow == srow or srow < first or erow > last:
            continue
        if (srow, scol) in docstrings:
            continue
        lines.update(range(srow + 1, erow + 1))
    return lines


def _require_calls(nodes: list[ast.stmt]) -> list[tuple[int, int, int]]:
    """``(line, col, end_col)`` of every ``_require()`` call in the nodes."""
    out = []
    for node in nodes:
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "_require"
                and not child.args
                and not child.keywords
            ):
                if child.end_lineno != child.lineno or child.end_col_offset is None:
                    raise SystemExit(f"_require() call spans lines at {child.lineno}")
                out.append((child.lineno, child.col_offset, child.end_col_offset))
    return out


def _runs(tree: ast.Module, modules: set[str]) -> list[tuple[str, list[ast.stmt]]]:
    runs: list[tuple[str, list[ast.stmt]]] = []
    previous_was_tool = False
    for node in tree.body:
        if _is_tool(node):
            module = _delegate(node, modules)
            if module is None:
                previous_was_tool = False
                continue
            if previous_was_tool and runs and runs[-1][0] == module:
                runs[-1][1].append(node)
            else:
                runs.append((module, [node]))
            previous_was_tool = True
        else:
            previous_was_tool = False
    return runs


def extract_helpers(server_src: str) -> tuple[str, str | None]:
    """Move MOVED_HELPERS out of server.py; return (new server source, _shared source)."""
    tree = ast.parse(server_src)
    nodes = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in MOVED_HELPERS
    ]
    if not nodes:
        return server_src, None
    lines = server_src.splitlines(keepends=True)
    pieces = []
    for node in nodes:
        pieces.append("".join(lines[_start(node) - 1 : node.end_lineno]))
    imports = _server_imports(tree)
    needed = _free_names(nodes)
    import_lines = []
    for name in needed:
        if name in imports:
            import_lines.append(_import_line(imports[name], "_shared"))
        elif name not in MOVED_HELPERS:
            raise SystemExit(f"helper name {name!r} has no server.py import to carry")
    import_lines.append("from ..config import Settings")
    blocks = [p.rstrip("\n") + "\n" for p in pieces] + list(FORWARDED.values())
    shared = (
        SHARED_HEADER + "\n" + "\n".join(sorted(set(import_lines))) + "\n\n\n" + "\n\n".join(blocks)
    )
    # Remove the helper definitions (and the blank lines after each) from server.py.
    drop: set[int] = set()
    for node in nodes:
        end = node.end_lineno or node.lineno
        while end < len(lines) and not lines[end].strip():
            end += 1
        drop.update(range(_start(node) - 1, end))
    kept = [line for i, line in enumerate(lines) if i not in drop]
    new_server = "".join(kept)
    # Import them back right after the ``from .tools import (...)`` statement.
    tree2 = ast.parse(new_server)
    anchor = next(
        n
        for n in tree2.body
        if isinstance(n, ast.ImportFrom) and n.module == "tools" and n.level == 1
    )
    lines2 = new_server.splitlines(keepends=True)
    insert = f"from .tools._shared import {', '.join(sorted(MOVED_HELPERS))}\n"
    lines2.insert(anchor.end_lineno or anchor.lineno, insert)
    return "".join(lines2), shared


def _indent_block(source: str, first: int, last: int) -> str:
    """Lines [first, last] of ``source`` indented by four spaces (string interiors kept)."""
    lines = source.splitlines(keepends=True)
    keep = _string_interiors(source, first, last)
    out = []
    for number in range(first, last + 1):
        line = lines[number - 1]
        if number in keep or not line.strip():
            out.append(line if line.strip() else "\n")
        else:
            out.append("    " + line)
    return "".join(out)


def move(selected: set[str] | None, check: bool) -> list[Path]:
    modules = _tool_modules()
    server_src = SERVER.read_text(encoding="utf-8")
    touched: list[Path] = []
    pending = []
    new_server, shared = extract_helpers(server_src)
    if shared is not None:
        pending.append("helpers")
        if not check:
            SHARED.write_text(shared, encoding="utf-8")
            touched.append(SHARED)
    tree = ast.parse(new_server)
    imports = _server_imports(tree)
    runs = [r for r in _runs(tree, modules) if selected is None or r[0] in selected]
    if not runs:
        if pending and not check:
            SERVER.write_text(new_server, encoding="utf-8")
            touched.append(SERVER)
        return [] if check and not pending else touched or ([SERVER] if pending else [])
    if check:
        return [SERVER]
    via_shared = set(MOVED_HELPERS) | set(FORWARDED)
    # Number each module's runs in file order.
    numbering: dict[int, str] = {}
    counts: dict[str, int] = {}
    for index, (module, _nodes) in enumerate(runs):
        counts[module] = counts.get(module, 0) + 1
        numbering[index] = "register" if counts[module] == 1 else f"register_{counts[module]}"
    lines = new_server.splitlines(keepends=True)
    additions: dict[str, list[tuple[str, str, list[str]]]] = {}
    for index in range(len(runs) - 1, -1, -1):
        module, nodes = runs[index]
        func = numbering[index]
        first, last = _start(nodes[0]), nodes[-1].end_lineno or nodes[-1].lineno
        # _require() -> deps_fn() inside the run (same line, so splice by columns).
        work = list(lines)
        for line_no, col, end_col in sorted(_require_calls(nodes), reverse=True):
            text = work[line_no - 1]
            work[line_no - 1] = text[:col] + "deps_fn()" + text[end_col:]
        block = _indent_block("".join(work), first, last)
        names = [n.name for n in nodes]
        additions.setdefault(module, []).insert(0, (func, block, names))
        holder = f"_{module}_tools" + ("" if func == "register" else func.removeprefix("register"))
        replacement = [f"{holder} = {module}.{func}(mcp, lambda: _require())\n"]
        replacement += [f'{name} = {holder}["{name}"]\n' for name in names]
        lines[first - 1 : last] = replacement
    SERVER.write_text("".join(lines), encoding="utf-8")
    touched.append(SERVER)
    for module, entries in additions.items():
        path = TOOLS / f"{module}.py"
        text = path.read_text(encoding="utf-8")
        target_tree = ast.parse(text)
        nodes_all = [
            n
            for n in ast.parse(new_server).body
            if _is_tool(n) and n.name in {name for _f, _b, names in entries for name in names}
        ]
        needed = _free_names(nodes_all)
        needed += [n for n in ("Callable", "Any", "FastMCP") if n not in needed]
        extra = {
            "Callable": "from collections.abc import Callable",
            "Any": "from typing import Any",
            "FastMCP": "from fastmcp import FastMCP",
        }
        have = _top_bindings(target_tree)
        new_imports = []
        for name in needed:
            if name in extra and name not in imports:
                if name not in have:
                    new_imports.append(extra[name])
                continue
            new_imports += _needed_imports([name], imports, target_tree, module, via_shared)
        functions = []
        for func, block, names in entries:
            returned = ", ".join(f'"{n}": {n}' for n in names)
            functions.append(
                f"\n\ndef {func}(\n"
                "    mcp: FastMCP, deps_fn: Callable[..., Any]\n"
                ") -> dict[str, Callable[..., Any]]:\n"
                f'    """Register the {module} tool wrappers moved from server.py, in order.\n'
                "\n"
                "    Returns the registered wrapper functions by name; server.py re-exports them.\n"
                '    """\n'
                "\n"
                f"{block.rstrip()}\n"
                "\n"
                f"    return {{{returned}}}\n"
            )
        # Sibling tools modules are imported after this module's own definitions, so a
        # sibling that imports a name from this module never sees it half-built.
        siblings = sorted(
            {
                line.removeprefix("from . import ")
                for line in new_imports
                if line.startswith("from . import ")
            }
        )
        top = sorted({line for line in new_imports if not line.startswith("from . import ")})
        tlines = text.splitlines(keepends=True)
        if top:
            last_import = max(
                (n.end_lineno or n.lineno)
                for n in target_tree.body
                if isinstance(n, (ast.Import, ast.ImportFrom))
            )
            tlines.insert(last_import, "".join(f"{line}\n" for line in top))
        text = "".join(tlines).rstrip("\n") + "\n"
        if siblings:
            text += (
                "\n\n# Tool modules the wrappers below delegate to, imported after this module's\n"
                "# own definitions so a module importing from this one never sees it half-built.\n"
                f"from . import {', '.join(siblings)}  # noqa: E402\n"
            )
        text += "".join(functions)
        path.write_text(text, encoding="utf-8")
        touched.append(path)
    _register_modules(list(additions))
    touched.append(PKG / "families.py")
    _long_docstring_ignores(list(additions))
    return touched


def _register_modules(modules: list[str]) -> None:
    """Add the modules to families._REGISTER_MODULES (sorted tail, idempotent)."""
    path = PKG / "families.py"
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.AnnAssign)
        and isinstance(n.target, ast.Name)
        and n.target.id == "_REGISTER_MODULES"
    )
    if not isinstance(node.value, ast.Tuple):
        raise SystemExit("families._REGISTER_MODULES is not a tuple literal")
    current = [elt.value for elt in node.value.elts if isinstance(elt, ast.Constant)]
    add = [m for m in sorted(modules) if m not in current]
    if not add:
        return
    lines = text.splitlines(keepends=True)
    close = node.end_lineno or node.lineno
    lines[close - 1 : close - 1] = [f'    "{m}",\n' for m in add]
    path.write_text("".join(lines), encoding="utf-8")


PYPROJECT = ROOT / "pyproject.toml"
_IGNORE_ANCHOR = "[tool.ruff.lint.per-file-ignores]\n"


def _long_docstring_ignores(modules: list[str]) -> None:
    """Allow long lines in modules that received wrappers.

    Nesting adds four spaces to every docstring line; re-wrapping the text would change
    the published tool descriptions, so E501 is waived for those files instead.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    entries = ""
    for module in sorted(modules):
        key = f'"src/unifi_fabric/tools/{module}.py" = ["E501"]'
        if key not in text:
            entries += f"{key}  # wrappers moved from server.py keep their docstrings\n"
    if entries:
        text = text.replace(_IGNORE_ANCHOR, _IGNORE_ANCHOR + entries, 1)
        PYPROJECT.write_text(text, encoding="utf-8")


def _ruff(paths: list[Path]) -> None:
    if not paths:
        return
    files = [str(p) for p in dict.fromkeys(paths)]
    ruff = [sys.executable, "-m", "ruff"]
    subprocess.run([*ruff, "check", "--fix", "--select", "I,F401", *files], check=False)
    subprocess.run([*ruff, "format", *files], check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", help="comma-separated tools modules to move (default: all)")
    parser.add_argument("--check", action="store_true", help="exit 1 when a run would still move")
    args = parser.parse_args(argv)
    selected = {m.strip() for m in args.modules.split(",")} if args.modules else None
    touched = move(selected, args.check)
    if args.check:
        return 1 if touched else 0
    _ruff(touched)
    for path in dict.fromkeys(touched):
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
