#!/usr/bin/env python3
"""Reject elapsed-time caps in tracked source, tests, scripts, and workflows."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = Path("docs/no-timeouts-allowlist.json")
SCAN_ROOTS = (
    "src/",
    "tests/",
    "scripts/",
    "docs/",
    "docs" + "/" + "internal" + "/",
    ".github/scripts/",
    ".github/workflows/",
    ".github/",
)
TOML_GATE = Path("scripts/doc_links.toml")
DOCKERFILE = Path("Dockerfile")
MARKDOWN_CODE = re.compile(r"```([A-Za-z0-9_+-]*)\s*\n(.*?)```", re.DOTALL)

SHELL_CAPS = re.compile(
    r"(?:^|[;&|]\s*|:\s*|\s)(?:g?timeout)(?:\s|$)"
    r"|curl\b(?:[^\n]*\\\n)*[^\n]*(?:--max-time|--connect-timeout|(?:^|\s)-[mM](?:\s|[0-9]))",
    re.MULTILINE,
)


def _is_none(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_qualified_timeout(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "Timeout"
    if isinstance(func, ast.Attribute):
        return func.attr == "Timeout"
    return False


def _is_time_arg(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
    if isinstance(node, (ast.Name, ast.Attribute)):
        name = node.id if isinstance(node, ast.Name) else node.attr
        return _contains_time_word(name)
    if isinstance(node, ast.BinOp):
        numeric_pair = (
            isinstance(node.left, ast.Constant)
            and isinstance(node.right, ast.Constant)
            and _is_time_arg(node.left)
            and _is_time_arg(node.right)
        )
        return _contains_time_name(node) or numeric_pair
    if isinstance(node, ast.Call):
        function = node.func
        call_name = function.id if isinstance(function, ast.Name) else getattr(function, "attr", "")
        if call_name in {"getenv", "get"}:
            return any(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and _contains_time_word(arg.value)
                for arg in node.args
            )
        if call_name in {"int", "float", "Decimal"}:
            return any(_is_time_arg(arg) for arg in node.args)
        return any(_is_time_arg(arg) for arg in node.args)
    return False


def _contains_time_word(name: str) -> bool:
    return any(
        word in name.casefold()
        for word in (
            "timeout",
            "deadline",
            "budget",
            "limit",
            "seconds",
            "duration",
            "delay",
            "grace",
            "interval",
        )
    )


def _contains_time_name(node: ast.AST) -> bool:
    return any(
        isinstance(item, (ast.Name, ast.Attribute))
        and _contains_time_word(item.id if isinstance(item, ast.Name) else item.attr)
        for item in ast.walk(node)
    )


def _is_waitable_receiver(node: ast.expr) -> bool:
    if not isinstance(node, ast.Name):
        return False
    name = node.id.casefold()
    return any(
        token in name
        for token in (
            "thread",
            "worker",
            "process",
            "proc",
            "future",
            "task",
            "event",
            "lock",
            "semaphore",
            "condition",
            "server",
            "child",
        )
    )


def python_findings(path: Path, text: str) -> list[str]:
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return [f"{path}:{exc.lineno or 1}: Python parse error during timeout scan"]
    found: list[str] = []
    scope: list[tuple[str, str | None]] = []
    waitable_names: set[str] = set()

    def is_demo(pathname: Path) -> bool:
        return pathname.as_posix() == "scripts/demo/demo.py"

    def allowed_demo_wait(func: ast.expr, args: list[ast.expr]) -> bool:
        if not is_demo(path) or not isinstance(func, ast.Attribute) or func.attr != "wait":
            return False
        receiver = func.value
        current_class, current_function = scope[-1] if scope else ("", None)
        allowed_receiver = (
            (
                current_class == "Screen"
                and current_function in {"think", "user", "say"}
                and isinstance(receiver, ast.Name)
                and receiver.id == "self"
            )
            or (
                current_class == "Session"
                and current_function == "tool"
                and isinstance(receiver, ast.Name)
                and receiver.id == "s"
            )
            or (
                current_class is None
                and current_function == "main"
                and isinstance(receiver, ast.Name)
                and receiver.id == "screen"
            )
        )
        if not allowed_receiver or len(args) != 1:
            return False
        argument = args[0]
        if current_class is None and current_function == "main":
            return True
        return (
            isinstance(argument, ast.Constant)
            and isinstance(argument.value, (int, float))
            and not isinstance(argument.value, bool)
        ) or (isinstance(argument, ast.Name) and argument.id == "seconds")

    def allowed_demo_clock(expression: ast.expr) -> bool:
        if not is_demo(path) or not scope:
            return False
        current_class, current_function = scope[-1]
        if current_class == "Screen" and current_function == "wait":
            if (
                isinstance(expression, ast.BinOp)
                and isinstance(expression.op, ast.Add)
                and is_monotonic(expression.left)
                and isinstance(expression.right, ast.BinOp)
                and isinstance(expression.right.op, ast.Mult)
                and isinstance(expression.right.left, ast.Name)
                and expression.right.left.id == "seconds"
                and isinstance(expression.right.right, ast.Name)
                and expression.right.right.id == "PACE"
            ):
                return True
            return (
                isinstance(expression, ast.Compare)
                and len(expression.ops) == 1
                and isinstance(expression.ops[0], ast.Lt)
                and is_monotonic(expression.left)
                and len(expression.comparators) == 1
                and isinstance(expression.comparators[0], ast.Name)
                and expression.comparators[0].id == "end"
            )
        if current_class == "Session" and current_function == "tool":
            return (
                isinstance(expression, ast.Compare)
                and len(expression.ops) == 1
                and isinstance(expression.ops[0], ast.Lt)
                and len(expression.comparators) == 1
                and is_monotonic_arithmetic(expression.left)
                and isinstance(expression.left, ast.BinOp)
                and isinstance(expression.left.op, ast.Sub)
                and isinstance(expression.left.right, ast.Name)
                and expression.left.right.id == "started"
                and isinstance(expression.comparators[0], ast.BinOp)
                and isinstance(expression.comparators[0].op, ast.Mult)
                and isinstance(expression.comparators[0].left, ast.Name)
                and expression.comparators[0].left.id == "min_s"
                and isinstance(expression.comparators[0].right, ast.Name)
                and expression.comparators[0].right.id == "PACE"
            )
        return False

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            if isinstance(node.value, ast.Call):
                constructor = node.value.func
                constructor_name = (
                    constructor.id
                    if isinstance(constructor, ast.Name)
                    else constructor.attr
                    if isinstance(constructor, ast.Attribute)
                    else ""
                )
                if constructor_name in {
                    "Thread",
                    "Process",
                    "Popen",
                    "Future",
                    "Event",
                    "Condition",
                    "Semaphore",
                }:
                    waitable_names.update(
                        target.id for target in node.targets if isinstance(target, ast.Name)
                    )
            raw_helper = any(
                isinstance(target, ast.Name) and target.id == "RAW_HELPER"
                for target in node.targets
            )
            if (
                raw_helper
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                found.extend(python_findings(path, node.value.value))
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            raw_helper = isinstance(node.target, ast.Name) and node.target.id == "RAW_HELPER"
            if (
                raw_helper
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                found.extend(python_findings(path, node.value.value))
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            scope.append((node.name, None))
            self.generic_visit(node)
            scope.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            current_class = scope[-1][0] if scope else None
            scope.append((current_class, node.name))
            self.generic_visit(node)
            scope.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else (func.id if isinstance(func, ast.Name) else "")
            )
            for keyword in node.keywords:
                if keyword.arg == "deadline" and not _is_none(keyword.value):
                    found.append(f"{path}:{node.lineno}: deadline keyword")
                if keyword.arg in {
                    "timeout",
                    "timeout_minutes",
                    "max_time",
                    "connect_timeout",
                } and not _is_none(keyword.value):
                    found.append(f"{path}:{node.lineno}: {keyword.arg} argument")
            if _is_qualified_timeout(func) and any(not _is_none(arg) for arg in node.args):
                found.append(f"{path}:{node.lineno}: positional HTTP client timeout")
            if name == "Timeout":
                for keyword in node.keywords:
                    if keyword.arg in {"connect", "read", "write", "pool"} and not _is_none(
                        keyword.value
                    ):
                        found.append(f"{path}:{node.lineno}: HTTP client timeout component")
            if name == "wait_for":
                found.append(f"{path}:{node.lineno}: wait_for call")
            if name in {"wait", "join", "communicate", "result", "exception"} and node.args:
                receiver = func.value if isinstance(func, ast.Attribute) else None
                asyncio_wait = (
                    name == "wait" and isinstance(receiver, ast.Name) and receiver.id == "asyncio"
                )
                if (
                    not asyncio_wait
                    and not allowed_demo_wait(func, node.args)
                    and any(_is_time_arg(arg) for arg in node.args)
                    or (
                        not asyncio_wait
                        and not allowed_demo_wait(func, node.args)
                        and receiver is not None
                        and (
                            _is_waitable_receiver(receiver)
                            or (isinstance(receiver, ast.Name) and receiver.id in waitable_names)
                        )
                        and node.args
                    )
                ):
                    found.append(f"{path}:{node.lineno}: timed {name} call")
            self.generic_visit(node)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            if (
                isinstance(node.op, ast.Add)
                and (is_monotonic(node.left) or is_monotonic(node.right))
                and not allowed_demo_clock(node)
            ):
                found.append(f"{path}:{node.lineno}: monotonic clock plus budget")
            self.generic_visit(node)

        def visit_Compare(self, node: ast.Compare) -> None:
            if any(
                is_monotonic(expr) or is_monotonic_arithmetic(expr)
                for expr in [node.left, *node.comparators]
            ) and not allowed_demo_clock(node):
                found.append(f"{path}:{node.lineno}: monotonic clock comparison")
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def is_monotonic(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "monotonic"
    )


def is_monotonic_arithmetic(node: ast.expr) -> bool:
    return isinstance(node, ast.BinOp) and (is_monotonic(node.left) or is_monotonic(node.right))


def workflow_findings(path: Path, text: str) -> list[str]:
    found: list[str] = []
    # 7200 removes GitHub's implicit 360-minute cap on self-hosted
    # jobs. Only this platform maximum is permitted, never step-level caps.
    job_blocks = re.split(r"(?m)(?=^  [A-Za-z0-9_-]+:\s*$)", text)
    allowed_lines: set[int] = set()
    offset = 0
    for block in job_blocks:
        lines = block.splitlines()
        if re.search(r"(?m)^    runs-on: .*\bself-hosted\b", block):
            for index, line in enumerate(lines, 1):
                runner = next(
                    (
                        item.removeprefix("    runs-on: ")
                        for item in lines
                        if item.startswith("    runs-on: ")
                    ),
                    "",
                )
                # A configurable runner uses the maximum for its selected platform.
                conditional = (
                    "    timeout-minutes: ${{ contains("
                    + runner[4:-3]
                    + ", 'self-hosted') && 7200 || 360 }}"
                    if runner.startswith("${{ fromJSON(") and runner.endswith(" }}")
                    else ""
                )
                if line == "    timeout-minutes: 7200" or line == conditional:
                    allowed_lines.add(offset + index)
        offset += len(lines)
    for line_number, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*(?:timeout-minutes|deadline)\s*:", line):
            if line_number not in allowed_lines:
                found.append(f"{path}:{line_number}: workflow cap setting")
    for line_number, command in _logical_shell_lines(text):
        if SHELL_CAPS.search(command):
            found.append(f"{path}:{line_number}: shell time cap")
    return found


def toml_findings(path: Path, text: str) -> list[str]:
    return [
        f"{path}:{line_number}: TOML time cap setting"
        for line_number, line in enumerate(text.splitlines(), 1)
        if re.match(r"\s*(?:timeout(?:[-_]minutes)?|deadline|max_time|connect_timeout)\s*=", line)
    ]


def scan_text(path: Path, text: str) -> list[str]:
    if path == ALLOWLIST:
        return []
    suffix = path.suffix.casefold()
    if suffix == ".py":
        return python_findings(path, text)
    if suffix in {".yml", ".yaml"}:
        return workflow_findings(path, text)
    if suffix == ".toml":
        return toml_findings(path, text)
    if suffix == ".sh":
        return [
            f"{path}:{line_number}: shell time cap"
            for line_number, command in _logical_shell_lines(text)
            if SHELL_CAPS.search(command)
        ]
    if suffix == ".md":
        findings: list[str] = []
        extensions = {
            "python": ".py",
            "py": ".py",
            "bash": ".sh",
            "sh": ".sh",
            "shell": ".sh",
            "yaml": ".yml",
            "yml": ".yml",
            "toml": ".toml",
            "dockerfile": ".dockerfile",
        }
        for match in MARKDOWN_CODE.finditer(text):
            language = match.group(1).casefold()
            extension = extensions.get(language)
            if extension is None:
                continue
            block = textwrap.dedent(match.group(2))
            block_findings = scan_text(path.with_suffix(extension), block)
            if extension == ".py" and any("Python parse error" in item for item in block_findings):
                if re.search(
                    r"\b(?:timeout|deadline)\s*=|\bwait_for\s*\(|\bTimeout\s*\("
                    r"|\.(?:join|wait|communicate|result|exception)\s*\("
                    r"|\btime\.monotonic\s*\([^)]*\)\s*[+<>=-]",
                    block,
                ):
                    block_findings = [
                        f"{path.with_suffix(extension)}:1: timeout token in Python fence"
                    ]
                else:
                    block_findings = []
            line_offset = text[: match.start(2)].count("\n")
            for finding in block_findings:
                relative = re.match(r"^.+?:(\d+):(.*)$", finding)
                if relative:
                    findings.append(
                        f"{path}:{line_offset + int(relative.group(1))}:{relative.group(2)}"
                    )
                else:
                    findings.append(finding.replace(str(path.with_suffix(extension)), str(path)))
        return findings
    if path == DOCKERFILE or suffix == ".dockerfile":
        return [
            f"{path}:{line_number}: Docker HEALTHCHECK cap"
            for line_number, line in enumerate(text.splitlines(), 1)
            if re.match(r"\s*HEALTHCHECK\b", line, re.IGNORECASE)
            and re.search(r"(?:^|\s)--(?:timeout|start-period|interval|retries)(?:=|\s)", line)
        ]
    return []


def _logical_shell_lines(text: str) -> list[tuple[int, str]]:
    commands: list[tuple[int, str]] = []
    start: int | None = None
    parts: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if start is None:
            start = number
        if not parts and line.lstrip().startswith("#"):
            start = None
            continue
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1] + " ")
            continue
        parts.append(line)
        commands.append((start, "".join(parts)))
        start = None
        parts = []
    if parts and start is not None:
        commands.append((start, "".join(parts)))
    return commands


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True)
    paths = [Path(item.decode()) for item in result.stdout.split(b"\0") if item]
    return [
        path
        for path in paths
        if (
            path == TOML_GATE
            or path.as_posix().startswith(".github/")
            or path.as_posix().startswith(SCAN_ROOTS)
            or path == Path("docs/no-timeouts-allowlist.json")
            or path == DOCKERFILE
        )
        and path != ALLOWLIST
        and (
            path == DOCKERFILE
            or path.suffix.casefold() in {".py", ".sh", ".yml", ".yaml", ".toml"}
            or (
                path.suffix.casefold() == ".md"
                and (path.parts[:1] == ("docs",) or path.parent == Path("."))
            )
        )
    ]


def check_allowlist(root: Path) -> list[str]:
    try:
        entries = json.loads((root / ALLOWLIST).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{ALLOWLIST}: invalid JSON ({exc})"]
    if not isinstance(entries, list):
        return [f"{ALLOWLIST}: root must be a JSON array"]
    required = {"path", "pattern", "class", "citation", "verdict", "added"}
    approved = {
        "Dockerfile",
        "docs/TLS.md",
    }
    expected_pattern = "HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3"
    expected_citation = "https://docs.docker.com/reference/dockerfile/#healthcheck"

    private_verdict = "public-platform-healthcheck"
    public_verdict = "public-platform-healthcheck"
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != required:
            return [f"{ALLOWLIST}[{index}]: entry must use the exact six-field schema"]
        if (
            entry["path"] not in approved
            or entry["path"] in seen
            or entry["pattern"] != expected_pattern
            or entry["class"] != "platform-mandated-maximum"
            or entry["citation"] != expected_citation
            or entry["verdict"] not in {private_verdict, public_verdict}
            or entry["added"] != "2026-10-23"
        ):
            return [
                f"{ALLOWLIST}[{index}]: entry does not match the approved healthcheck exception"
            ]
        seen.add(entry["path"])
    if seen != approved:
        return [f"{ALLOWLIST}: approved Docker healthcheck entries are missing"]
    return []


def repository_findings(root: Path) -> list[str]:
    allowlist_findings = check_allowlist(root)
    findings: list[str] = []
    for path in tracked_paths(root):
        try:
            text = (root / path).read_text()
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(scan_text(path, text))
    if allowlist_findings:
        return allowlist_findings + findings
    entries = json.loads((root / ALLOWLIST).read_text())
    approved_locations: set[tuple[str, int]] = set()
    stale: list[str] = []
    for entry in entries:
        path = entry["path"]
        source = root / path
        try:
            lines = source.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            stale.append(f"{ALLOWLIST}: stale exception for missing {path}")
            continue
        line_numbers = {number for number, line in enumerate(lines, 1) if entry["pattern"] in line}
        matching = {
            location
            for finding in findings
            if (location := finding_location(finding)) is not None
            and location[0] == path
            and location[1] in line_numbers
        }
        if not matching:
            stale.append(f"{ALLOWLIST}: stale exception pattern for {path}")
        approved_locations.update(matching)
    remaining = [
        finding
        for finding in findings
        if (location := finding_location(finding)) not in approved_locations
    ]
    return stale + remaining


def finding_location(finding: str) -> tuple[str, int] | None:
    match = re.match(r"^(.+?):(\d+):", finding)
    return (match.group(1), int(match.group(2))) if match else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    findings = repository_findings(root)
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("No elapsed-time caps found in tracked source, tests, scripts, or workflows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
