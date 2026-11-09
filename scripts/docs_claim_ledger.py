#!/usr/bin/env python3
"""Documentation claim ledger: check mechanical doc claims against the source.

``--check`` exits non-zero on any false or stale mechanical claim and on any manual
entry whose doc text or source evidence is gone. ``--report PATH`` writes one JSON record
per claim: ``claim_id, doc (path:line), claim, kind, source (path:line or "manual"),
disposition, reviewer``.

Mechanical kinds are verified against the code: env-name / default / enum against the
settings models, tool-name against the registered tools, count against the registry,
link/anchor against the working tree, cli / exit-code / quoted-error / version against
the installed entry point and ``pyproject.toml``. Claims that need a human (prose
semantics, external citations) are recorded in ``docs_claim_ledger_manual.json`` next to
this script. Each manual entry locates its doc line and its source line by text
(``find`` and ``source_find``), so a moved claim or source is reported at its current line
and a deleted one as stale, rather than silently pointing at the wrong line.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import importlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Literal, TypedDict, get_args, get_origin
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MANUAL_FILE = Path(__file__).with_name("docs_claim_ledger_manual.json")
MECHANICAL_REVIEWER = "docs_claim_ledger.py"
KINDS = (
    "env-name",
    "default",
    "enum",
    "tool-name",
    "count",
    "link/anchor",
    "cli",
    "exit-code",
    "version",
    "quoted-error",
    "manual",
)
DISPOSITIONS = ("verified", "corrected", "historical", "manual-accepted")

ENV_RE = re.compile(r"\b(?:UNIFI|MCP)_[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*\b")
TOOL_RE = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\((<[^>]+>|[^)\s]+)(?:\s+[^)]*)?\)")
CLI_RE = re.compile(r"`(unifi-fabric-mcp(?:\s+[^`\n]+)?)`")
PIN_RE = re.compile(r"unifi-fabric-mcp-server(?:==|:|@v?|=)(\d+\.\d+\.\d+)")
COUNT_RE = re.compile(r"\b(\d[\d,]*)\s+(?:registered\s+)?tools\b", re.I)
HISTORICAL_RE = re.compile(
    r"historical|previous|earlier|formerly|renamed|removed|deprecated|legacy|was `|were `|"
    r"before 0\.|since 0\.|upgrad|migrat",
    re.I,
)
SUBCOMMANDS = ("placement-snapshot", "placement-snapshot-preflight")
VERBS = (
    "get|list|create|update|delete|set|add|remove|start|stop|run|query|search|enable|disable|"
    "adopt|reboot|restart|upgrade|export|import|trigger|block|unblock|play|reset|locate"
)


class Record(TypedDict):
    """One ledger row (the JSON report schema)."""

    claim_id: str
    doc: str
    claim: str
    kind: str
    source: str
    disposition: str
    reviewer: str


class Finding(TypedDict):
    """A false or stale claim that fails ``--check``."""

    doc: str
    claim: str
    kind: str
    problem: str


def _doc_files(root: Path) -> list[Path]:
    files = [root / "README.md", root / "AGENTS.md", root / "CONTRIBUTING.md"]
    files += sorted(p for p in (root / "docs").glob("*.md") if p.name != "TOOLS.md")
    files += sorted((root / "plugins").glob("*/README.md"))
    return [p for p in files if p.is_file()]


def _heading_anchors(path: Path) -> frozenset[str]:
    seen: dict[str, int] = {}
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if match:
            label = re.sub(r"<[^>]*>", "", match.group(1)).lower()
            label = re.sub(r"[^\w\- ]", "", label).replace(" ", "-")
            n = seen.get(label, 0)
            seen[label] = n + 1
            out.add(label + (f"-{n}" if n else ""))
        out.update(re.findall(r"""<(?:a|span)\b[^>]*(?:id|name)=["']([^"']+)["']""", line))
    return frozenset(out)


class Source:
    """Everything the mechanical checks compare documentation against."""

    def __init__(self, root: Path) -> None:
        self.root = root
        sys.path.insert(0, str(root / "src"))
        saved = {
            k: v for k, v in os.environ.items() if k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))
        }
        for key in saved:
            del os.environ[key]
        os.environ["UNIFI_API_KEY"] = "claim-ledger-synthetic-key"
        os.environ["UNIFI_TOOL_MODE"] = "full"
        try:
            config = importlib.import_module("unifi_fabric.config")
            mcp = importlib.import_module("unifi_fabric.server").mcp

            self.registry = {t.name for t in asyncio.run(mcp.list_tools())}
            self.fields: dict[str, Any] = {}
            for cls in (config.Settings, config.MCPTransportSettings):
                for key, field in cls.model_fields.items():
                    alias = field.validation_alias
                    prefix = str(cls.model_config.get("env_prefix", ""))
                    name = alias if isinstance(alias, str) else prefix.upper() + key.upper()
                    self.fields[name] = field
        finally:
            for key in list(os.environ):
                if key.startswith(("UNIFI_", "MCP_", "FASTMCP_")):
                    del os.environ[key]
            os.environ.update(saved)
        self.version: str = tomllib.loads((root / "pyproject.toml").read_text())["project"][
            "version"
        ]
        published = root / "scripts" / "published-version.txt"
        self.published: str = published.read_text().strip() if published.is_file() else self.version
        self.tools_doc = set(
            re.findall(r"^### `([a-z][a-z0-9_]*)`\s*$", (root / "docs/TOOLS.md").read_text(), re.M)
        )
        self.literals: list[tuple[str, str, int]] = []
        self.identifiers: set[str] = set()
        for src in sorted((root / "src").rglob("*.py")):
            try:
                tree = ast.parse(src.read_text())
            except (SyntaxError, UnicodeError):
                continue
            rel = str(src.relative_to(root))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.literals.append((node.value, rel, node.lineno))
                elif isinstance(node, ast.Name):
                    self.identifiers.add(node.id)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.identifiers.add(node.name)
        self.env_known = set(self.fields) | {
            m for text, _, _ in self.literals for m in ENV_RE.findall(text)
        }
        # Variables read by the test harness and scripts are real, documented knobs too.
        for extra in (
            *sorted((root / "tests").glob("*.py")),
            *sorted((root / "scripts").rglob("*.py")),
        ):
            self.env_known.update(
                ENV_RE.findall(extra.read_text(encoding="utf-8", errors="replace"))
            )
        self.executable = str(Path(sys.executable).parent / "unifi-fabric-mcp")
        self.helps = {
            sub: self._run([*([sub] if sub else []), "--help"], key=False)[1]
            for sub in ("", *SUBCOMMANDS)
        }
        self.missing_key = self._run([], key=False)
        self.unknown_sub = self._run(["placement-snapsho"], key=True)

    def _run(self, args: list[str], key: bool) -> tuple[int, str]:
        env = {"PATH": os.defpath, "LANG": "C.UTF-8", "NO_PROXY": "*"}
        if key:
            env["UNIFI_API_KEY"] = "claim-ledger-synthetic-key"
        done = subprocess.run(
            [self.executable, *args],
            cwd=self.root,
            env=env,
            input="",
            capture_output=True,
            text=True,
            check=False,
        )
        return done.returncode, (done.stdout + done.stderr).strip()

    def literal_line(self, needle: str) -> str | None:
        for text, rel, line in self.literals:
            if needle in text:
                return f"{rel}:{line}"
        return None

    def field_source(self, env: str) -> str:
        field = self.fields.get(env)
        if field is None:
            return self.literal_line(env) or "src"
        text = (self.root / "src/unifi_fabric/config.py").read_text().splitlines()
        attr = env.removeprefix("UNIFI_").removeprefix("MCP_").lower()
        for number, line in enumerate(text, 1):
            if re.match(rf"\s+{re.escape(attr)}\s*:", line):
                return f"src/unifi_fabric/config.py:{number}"
        return "src/unifi_fabric/config.py"


def _literal_values(field: Any) -> set[str] | None:
    ann = field.annotation
    for candidate in (ann, *get_args(ann)):
        if get_origin(candidate) is Literal:
            return {str(v) for v in get_args(candidate)}
    return None


def _edit_distance(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class Ledger:
    """Builds records and findings for every doc line."""

    def __init__(self, root: Path = ROOT) -> None:
        self.root = root.resolve()
        self.src = Source(self.root)
        self.records: list[Record] = []
        self.findings: list[Finding] = []
        self._ids: dict[str, int] = {}
        self._anchors: dict[Path, frozenset[str]] = {}

    def add(
        self, doc: str, line: int, claim: str, kind: str, source: str, status: str, note: str
    ) -> None:
        """Record a mechanical result; ``status`` is verified / historical / false / stale."""
        base = f"{kind}:{doc}:{line}:{claim}"
        n = self._ids.get(base, 0)
        self._ids[base] = n + 1
        if status in ("false", "stale"):
            self.findings.append(
                {
                    "doc": f"{doc}:{line}",
                    "claim": claim,
                    "kind": kind,
                    "problem": f"{status}: {note}",
                }
            )
            return
        self.records.append(
            {
                "claim_id": f"{kind}-{doc.replace('/', '-')}-{line}-{len(self.records)}",
                "doc": f"{doc}:{line}",
                "claim": claim,
                "kind": kind,
                "source": source,
                "disposition": status,
                "reviewer": MECHANICAL_REVIEWER,
            }
        )

    # -- mechanical sweep ------------------------------------------------------------
    def sweep(self) -> None:
        for path in _doc_files(self.root):
            rel = str(path.relative_to(self.root))
            lines = path.read_text(encoding="utf-8").splitlines()
            for number, text in enumerate(lines, 1):
                context = " ".join(lines[max(0, number - 3) : number + 2])
                self._line(path, rel, number, text, context)

    def _line(self, path: Path, rel: str, number: int, text: str, context: str) -> None:
        src = self.src
        historical = bool(HISTORICAL_RE.search(context)) or rel.startswith("docs/MIGRATING-")
        for env in dict.fromkeys(ENV_RE.findall(text)):
            if env.endswith("_"):
                continue
            if env in src.env_known:
                self.add(rel, number, env, "env-name", src.field_source(env), "verified", "")
            elif historical:
                self.add(rel, number, env, "env-name", "manual", "historical", "")
            else:
                self.add(
                    rel, number, env, "env-name", "", "false", f"{env} is not read by the source"
                )
        self._config_row(rel, number, text)
        for name in dict.fromkeys(TOOL_RE.findall(text)):
            if name in src.registry:
                self.add(rel, number, name, "tool-name", "registered tool", "verified", "")
            elif name in src.tools_doc:
                self.add(
                    rel,
                    number,
                    name,
                    "tool-name",
                    "docs/TOOLS.md",
                    "stale",
                    f"{name} is documented in TOOLS.md but not registered",
                )
            elif (
                re.match(rf"({VERBS})_", name)
                and not historical
                and name not in src.identifiers
                and not src.literal_line(name)
                and any(_edit_distance(name, t) <= 2 for t in src.registry)
            ):
                near = min(src.registry, key=lambda t: _edit_distance(name, t))
                self.add(
                    rel,
                    number,
                    name,
                    "tool-name",
                    "",
                    "false",
                    f"{name} is not a tool; near miss of {near}",
                )
        for match in LINK_RE.finditer(text):
            self._link(path, rel, number, match.group(1).strip("<>"))
        for match in COUNT_RE.finditer(text):
            prefix = text[max(0, match.start() - 30) : match.start()].lower()
            if re.search(r"(?:this release.s|all|registered|exposes|total)\s*$", prefix):
                claimed = int(match.group(1).replace(",", ""))
                if claimed == len(src.registry) == len(src.tools_doc):
                    self.add(
                        rel, number, match.group(0), "count", "registered tools", "verified", ""
                    )
                elif historical:
                    self.add(rel, number, match.group(0), "count", "manual", "historical", "")
                else:
                    self.add(
                        rel,
                        number,
                        match.group(0),
                        "count",
                        "registered tools",
                        "stale",
                        f"registry has {len(src.registry)}",
                    )
        for command in CLI_RE.findall(text):
            self._cli(rel, number, command)
        for pin in PIN_RE.findall(text):
            if pin == src.version:
                self.add(rel, number, pin, "version", "pyproject.toml", "verified", "")
            elif pin == src.published:
                self.add(
                    rel, number, pin, "version", "scripts/published-version.txt", "verified", ""
                )
            elif historical:
                self.add(rel, number, pin, "version", "pyproject.toml", "historical", "")
            else:
                self.add(
                    rel,
                    number,
                    pin,
                    "version",
                    "pyproject.toml",
                    "stale",
                    f"pyproject version is {src.version}",
                )
        if "UNIFI_API_KEY is not set" in text:
            code, out = src.missing_key
            ok = code == 1 and "UNIFI_API_KEY is not set" in out
            self.add(
                rel,
                number,
                "UNIFI_API_KEY is not set",
                "exit-code",
                "executed entry point",
                "verified" if ok else "false",
                f"exit {code}",
            )
            found = src.literal_line("UNIFI_API_KEY is not set")
            self.add(
                rel,
                number,
                "UNIFI_API_KEY is not set",
                "quoted-error",
                found or "",
                "verified" if found else "false",
                "no such literal in src",
            )
        if (
            re.search(r"exits? with (?:status|code) 2", text, re.I)
            and "unknown subcommand" in context.lower()
        ):
            code, out = src.unknown_sub
            ok = code == 2 and "did you mean" in out.lower()
            self.add(
                rel,
                number,
                "unknown subcommand exits 2",
                "exit-code",
                "executed entry point",
                "verified" if ok else "false",
                f"exit {code}",
            )

    def _config_row(self, rel: str, number: int, text: str) -> None:
        match = re.match(r"\|\s*`((?:UNIFI|MCP)_[A-Z0-9_]+)`\s*\|(.*)\|\s*$", text)
        field = self.src.fields.get(match.group(1)) if match else None
        if not match or field is None:
            return
        env = match.group(1)
        cells = [c.strip() for c in match.group(2).split("|")]
        default = field.default
        if isinstance(default, (bool, int)):
            expected = str(default).lower()
            for cell in cells[:2]:
                token = cell.strip("`").lower()
                if re.fullmatch(r"-?\d+|true|false", token) and cell.startswith("`"):
                    status = "verified" if token == expected else "stale"
                    self.add(
                        rel,
                        number,
                        f"{env} default {token}",
                        "default",
                        self.src.field_source(env),
                        status,
                        f"declared default is {expected}",
                    )
                    break
        elif isinstance(default, str) and default:
            for cell in cells[:2]:
                if cell == f"`{default}`":
                    self.add(
                        rel,
                        number,
                        f"{env} default {default}",
                        "default",
                        self.src.field_source(env),
                        "verified",
                        "",
                    )
        accepted = _literal_values(field)
        if accepted:
            tokens = {t for cell in cells[1:] for t in re.findall(r"`([^`]+)`", cell)}
            if len(tokens & accepted) >= 2:
                for token in sorted(tokens):
                    near = token not in accepted and any(
                        _edit_distance(token, a) <= 2 for a in accepted
                    )
                    if token in accepted or near:
                        self.add(
                            rel,
                            number,
                            f"{env} accepts {token}",
                            "enum",
                            self.src.field_source(env),
                            "false" if near else "verified",
                            f"not in {sorted(accepted)}",
                        )

    def _link(self, path: Path, rel: str, number: int, target: str) -> None:
        url = urlsplit(target)
        if url.scheme or url.netloc:
            return
        dest = (path.parent / unquote(url.path)).resolve() if url.path else path.resolve()
        try:
            dest.relative_to(self.root)
        except ValueError:
            return
        label = target
        if not dest.exists():
            self.add(rel, number, label, "link/anchor", "", "false", "target missing")
        elif url.fragment and dest.suffix.lower() == ".md":
            anchors = self._anchors.setdefault(dest, _heading_anchors(dest))
            if unquote(url.fragment) in anchors:
                self.add(
                    rel,
                    number,
                    label,
                    "link/anchor",
                    str(dest.relative_to(self.root)),
                    "verified",
                    "",
                )
            else:
                self.add(rel, number, label, "link/anchor", "", "false", "anchor not found")
        else:
            self.add(
                rel, number, label, "link/anchor", str(dest.relative_to(self.root)), "verified", ""
            )

    def _cli(self, rel: str, number: int, command: str) -> None:
        parts = command.split()[1:]
        if not parts:
            return
        sub = parts[0] if not parts[0].startswith("-") else ""
        helptext = self.src.helps.get(sub)
        if helptext is None:
            self.add(rel, number, command, "cli", "", "false", f"{sub}: not a subcommand")
            return
        flags = [p.split("=", 1)[0] for p in parts if p.startswith("--")]
        missing = [
            f for f in flags if not re.search(r"(?<![\w-])" + re.escape(f) + r"(?![\w-])", helptext)
        ]
        status = "false" if missing else "verified"
        self.add(
            rel,
            number,
            command,
            "cli",
            "executed --help",
            status,
            f"flags missing from --help: {missing}",
        )

    # -- manual entries ---------------------------------------------------------------
    def manual(self) -> None:
        entries = json.loads(MANUAL_FILE.read_text(encoding="utf-8"))
        for entry in entries:
            doc, find = str(entry["doc"]), str(entry["find"])
            path = self.root / doc
            line = (
                next(
                    (
                        n
                        for n, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                        if find in text
                    ),
                    None,
                )
                if path.is_file()
                else None
            )
            problem = ""
            if line is None:
                problem = f"doc text {find!r} not found in {doc}"
            source = str(entry["source"])
            expect = entry.get("source_find")
            if not problem and source != "manual":
                src_path = self.root / source
                src_text = src_path.read_text(encoding="utf-8") if src_path.is_file() else ""
                if ":" in source or not expect:
                    problem = (
                        f"source {source!r} must be a file path with a source_find text "
                        "(its line is resolved from that text)"
                    )
                elif not src_path.is_file():
                    problem = f"source file {source} missing"
                elif expect not in src_text:
                    problem = f"source {source} no longer contains {expect!r}"
                else:
                    source = f"{source}:{src_text[: src_text.index(expect)].count(chr(10)) + 1}"
            if entry["kind"] not in KINDS or entry["disposition"] not in DISPOSITIONS:
                problem = problem or "invalid kind or disposition"
            if problem:
                self.findings.append(
                    {
                        "doc": f"{doc}:{line or '?'}",
                        "claim": str(entry["claim"]),
                        "kind": str(entry["kind"]),
                        "problem": f"stale: {problem}",
                    }
                )
                continue
            self.records.append(
                {
                    "claim_id": str(entry["claim_id"]),
                    "doc": f"{doc}:{line}",
                    "claim": str(entry["claim"]),
                    "kind": str(entry["kind"]),
                    "source": source,
                    "disposition": str(entry["disposition"]),
                    "reviewer": str(entry["reviewer"]),
                }
            )

    def run(self) -> None:
        self.sweep()
        self.manual()

    def summary(self) -> dict[str, int]:
        counts = {"claims": len(self.records), "false_or_stale": len(self.findings)}
        for name in DISPOSITIONS:
            counts[name] = sum(1 for r in self.records if r["disposition"] == name)
        counts["manual_entries"] = sum(
            1 for r in self.records if r["reviewer"] != MECHANICAL_REVIEWER
        )
        return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument(
        "--check", action="store_true", help="exit non-zero on a false or stale claim"
    )
    parser.add_argument("--report", type=Path, help="write the JSON claim records to this path")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    ledger = Ledger(args.root)
    ledger.run()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        payload = {"summary": ledger.summary(), "records": ledger.records}
        args.report.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
    summary = ledger.summary()
    parts = [f"{key}={summary[key]}" for key in ("claims", *DISPOSITIONS, "false_or_stale")]
    print(" ".join(parts))
    for finding in ledger.findings:
        print(
            f"{finding['doc']} [{finding['kind']}] {finding['claim']}: {finding['problem']}",
            file=sys.stderr,
        )
    if args.check and ledger.findings:
        print(f"docs claim ledger: {len(ledger.findings)} false or stale claim(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
