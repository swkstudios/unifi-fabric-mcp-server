#!/usr/bin/env python3
"""Tool-description eval: can an agent find the right tool and fill in its arguments?

A fixed set of 120 tasks (tests/fixtures/description_eval/tasks.json). Each task names the tool that
does it and the arguments it needs. 62 tasks are marked ``hard``: they state a value in plain words,
in another unit, or only by implication, so a worse description lowers the score.

Three measurements:

1. ``select`` (deterministic, no model): each task goes through the real discovery path,
   ``search_tools`` of the discovery-mode server. Top-1 and top-5 are recorded. The same step saves
   the ``describe_tool`` entry (name, description, input schema) of every tool.
2. ``llm`` search mode (a model): ``claude -p --model claude-haiku-5-5`` gets the task and the
   ``describe_tool`` entries of its five search results, picks one of the five and writes its
   arguments.
3. ``llm`` full mode (a model): the same model gets the task and the full ``tools/list`` entries of
   the whole family the task belongs to (name, description, input schema), picks one and writes its
   arguments. No search is involved.

Every model pass is repeated three times; the spread between the runs is the noise a description
change has to beat. To keep a full run under the token budget, tasks are sent in batches: search
mode sends up to twenty tasks of one family per call with the union of their candidate entries (each
task still lists its own five candidates); full mode sends all tasks of a family in one call with
that family's entries once. The tasks of a call are independent and the model is told so.

``report`` merges everything into the numbers committed in
tests/fixtures/description_eval/baseline.json: selection accuracy and argument accuracy for both
modes, the run-to-run spread, the hard tasks on their own, and the tokens spent.

Usage (``select`` needs the project environment; ``llm`` and ``report`` use the standard library and
the ``claude`` CLI, logged in)::

    python3 scripts/eval_descriptions.py select --out /tmp/selection.json
    python3 scripts/eval_descriptions.py llm --selection /tmp/selection.json --out /tmp/llm.json
    python3 scripts/eval_descriptions.py report --selection /tmp/selection.json \
        --llm /tmp/llm.json [--write-baseline]
    python3 scripts/eval_descriptions.py select --floor   # CI: selection vs the baseline floor

``llm`` refuses to start when its estimate exceeds ``--token-budget`` (default 3,000,000 tokens for
the whole run, both modes and every repeat included) and stops before a call that would pass it.
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "description_eval"
TASKS = FIXTURES / "tasks.json"
BASELINE = FIXTURES / "baseline.json"
MODEL = "claude-haiku-5-5"
RUNS = 3
TOKEN_BUDGET = 3_000_000
TOP_N = 5
#: Tasks per call in search mode (of one family; their candidate entries are sent once).
SEARCH_BATCH = 20
MODES = ("search", "full")
#: The describe_tool fields an agent needs. ``title`` repeats the name, ``_meta`` is server
#: bookkeeping, and annotations and the output schema do not help to choose a tool or its arguments.
ENTRY_KEYS = ("name", "description", "inputSchema")
#: Tokens per character used for the pre-run estimate (on the high side of what was measured).
CHARS_PER_TOKEN = 2.45
#: Fixed text around the tools and tasks (system prompt, rules), in tokens.
PROMPT_OVERHEAD_TOKENS = 700
#: Output tokens reserved for each task's answer.
ANSWER_TOKENS_PER_TASK = 110
USAGE_KEYS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)
#: ``select --floor`` tolerates this many tasks below the committed top-5 floor: adding tools or
#: editing descriptions legitimately moves a few tasks, and a larger fall is a real regression.
CHECK_SLACK_TASKS = 3

SYSTEM_PROMPT = "You pick tools for tasks and write their arguments. Output one JSON array only."
USER_TEMPLATE = """Tools (JSON, one object per tool: name, description, inputSchema):
{tools}

Pick a tool for each task below and write its arguments. Rules:
- The tasks are independent of each other.
- Use exactly one tool per task, chosen only from that task's candidates.
- Use only values the task states or implies; follow the tool's description and schema for names,
  units and formats.

Tasks:
{tasks}

Reply with only a JSON array with one object per task:
[{{"id": "t001", "tool": "<name>", "arguments": {{...}}}}, ...]"""


def load_tasks() -> list[dict[str, Any]]:
    return json.loads(TASKS.read_text())["tasks"]


def tasks_sha256() -> str:
    return hashlib.sha256(TASKS.read_bytes()).hexdigest()


_PREFIX = re.compile(r'^On the console "[^"]*"(, site "[^"]*")?: ')


def search_query(task: dict[str, Any]) -> str:
    """The text an agent would search with: the task without its console and site prefix."""
    return _PREFIX.sub("", task["task"])


# --------------------------------------------------------------------------- part 1: select


async def run_selection() -> dict[str, Any]:
    """Run every task through ``search_tools`` of the discovery server; save every tool entry."""
    saved = dict(os.environ)
    try:
        for name in [k for k in os.environ if k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))]:
            del os.environ[name]
        os.environ["UNIFI_API_KEY"] = "description-eval-placeholder-key"
        os.environ["UNIFI_TOOL_MODE"] = "full"
        from fastmcp import Client, FastMCP

        from unifi_fabric import server
        from unifi_fabric.discovery import apply_tool_mode
        from unifi_fabric.families import build_family_index

        app = FastMCP("description-eval")
        catalog = await server.mcp.list_tools()
        for tool in catalog:
            app.add_tool(tool)
        family_of = dict(build_family_index())
        cleanup = await apply_tool_mode(app, "discovery")
    finally:
        os.environ.clear()
        os.environ.update(saved)
    rows = []
    tools: dict[str, Any] = {}
    try:
        async with Client(app) as client:
            for task in load_tasks():
                found = await client.call_tool(
                    "search_tools", {"query": search_query(task), "limit": TOP_N}
                )
                rows.append(
                    {
                        "id": task["id"],
                        "top": [i["name"] for i in found.structured_content["result"]],
                    }
                )
            for tool in catalog:
                entry = (
                    await client.call_tool("describe_tool", {"name": tool.name})
                ).structured_content
                tools[tool.name] = {k: entry[k] for k in ENTRY_KEYS}
    finally:
        cleanup()
    return {
        "catalog_tools": len(catalog),
        "tasks_sha256": tasks_sha256(),
        "rows": rows,
        "tools": tools,
        "family_of": {name: family_of.get(name, "other") for name in tools},
    }


def selection_numbers(tasks: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Top-1 and top-5 hits, overall, by family and for the near-duplicate pairs."""
    by_id = {row["id"]: row["top"] for row in rows}

    def tally(subset: list[dict[str, Any]]) -> dict[str, Any]:
        top1 = sum(by_id[t["id"]][:1] == [t["expected_tool"]] for t in subset)
        top5 = sum(t["expected_tool"] in by_id[t["id"]] for t in subset)
        n = len(subset)
        return {
            "tasks": n,
            "top1": top1,
            "top5": top5,
            "top1_rate": _rate(top1, n),
            "top5_rate": _rate(top5, n),
        }

    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for t in tasks:
        families[t["family"]].append(t)
    return {
        "overall": tally(tasks),
        "near_duplicate_pairs": tally([t for t in tasks if t["pair"]]),
        "other_tasks": tally([t for t in tasks if not t["pair"]]),
        "hard_tasks": tally([t for t in tasks if t.get("hard")]),
        "by_family": {f: tally(ts) for f, ts in sorted(families.items())},
        "top5_misses": sorted(t["id"] for t in tasks if t["expected_tool"] not in by_id[t["id"]]),
    }


def _rate(hits: int, n: int) -> float:
    return round(hits / n, 4) if n else 0.0


# ------------------------------------------------------------------------ part 2: the model


def degrade(entry: dict[str, Any]) -> dict[str, Any]:
    """A deliberately worse entry: first sentence of the description, no parameter descriptions."""

    def strip(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                k: strip(v)
                for k, v in node.items()
                if not (k == "description" and isinstance(v, str))
            }
        if isinstance(node, list):
            return [strip(v) for v in node]
        return node

    first = re.split(r"(?<=[.!?])\s", entry["description"].strip(), maxsplit=1)[0]
    return {"name": entry["name"], "description": first, "inputSchema": strip(entry["inputSchema"])}


def make_batches(selection: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    """The calls of one run: each has its tasks, their candidate tools and the tools to send."""
    tasks = load_tasks()
    top = {row["id"]: row["top"] for row in selection["rows"]}
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for t in tasks:
        by_family[t["family"]].append(t)
    batches = []
    for family, members in sorted(by_family.items()):
        if mode == "full":
            names = sorted(n for n, f in selection["family_of"].items() if f == family)
            batches.append(
                {"tasks": members, "candidates": {t["id"]: None for t in members}, "tools": names}
            )
            continue
        for i in range(0, len(members), SEARCH_BATCH):
            chunk = members[i : i + SEARCH_BATCH]
            union = sorted({n for t in chunk for n in top[t["id"]]})
            batches.append(
                {
                    "tasks": chunk,
                    "candidates": {t["id"]: top[t["id"]] for t in chunk},
                    "tools": union,
                }
            )
    return batches


def build_prompt(batch: dict[str, Any], tools: dict[str, Any]) -> str:
    shown = [tools[name] for name in batch["tools"]]
    lines = []
    for task in batch["tasks"]:
        cand = batch["candidates"][task["id"]]
        where = ", ".join(cand) if cand else "any tool above"
        lines.append(f"{task['id']} | candidates: {where} | {task['task']}")
    return USER_TEMPLATE.format(
        tools=json.dumps(shown, separators=(",", ":"), ensure_ascii=False), tasks="\n".join(lines)
    )


def estimate_tokens(prompt: str, n_tasks: int) -> int:
    return (
        int(len(prompt) / CHARS_PER_TOKEN)
        + PROMPT_OVERHEAD_TOKENS
        + ANSWER_TOKENS_PER_TASK * n_tasks
    )


def call_model(prompt: str, model: str, retries: int = 2) -> dict[str, Any]:
    """One ``claude -p`` call. The prompt goes in on stdin; nothing secret is in argv."""
    command = [
        "claude", "-p", "--model", model, "--output-format", "json", "--tools", "",
        "--no-session-persistence", "--system-prompt", SYSTEM_PROMPT,
        "--setting-sources", "", "--disable-slash-commands", "--strict-mcp-config",
        "--effort", "low",
    ]  # fmt: skip
    tokens = 0
    for attempt in range(retries + 1):
        with tempfile.TemporaryDirectory(prefix="description-eval-") as cwd:  # no CLAUDE.md to load
            proc = subprocess.run(  # noqa: S603
                command,
                input=prompt,
                capture_output=True,
                text=True,
                cwd=cwd,
                check=False,
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            data = {"is_error": True, "result": f"unparseable output (exit {proc.returncode})"}
        usage = data.get("usage") or {}
        tokens += sum(int(usage.get(k) or 0) for k in USAGE_KEYS)
        if not data.get("is_error"):
            return {
                "error": None,
                "tokens": tokens,
                "answers": parse_answers(str(data.get("result") or "")),
            }
        if attempt < retries:
            time.sleep(30 * (attempt + 1))
    return {"error": str(data.get("result"))[:200], "tokens": tokens, "answers": {}}


def parse_answers(text: str) -> dict[str, dict[str, Any]]:
    """The answer objects of a reply by task id; objects without ``id`` and ``tool`` are skipped."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    decoder = json.JSONDecoder()
    found: dict[str, dict[str, Any]] = {}
    pos = 0
    while (start := text.find("{", pos)) != -1:
        try:
            obj, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            pos = start + 1
            continue
        if isinstance(obj, dict) and "id" in obj and "tool" in obj:
            found.setdefault(str(obj["id"]), obj)
            pos = start + end
        else:
            pos = start + 1  # look inside a wrapper object for the answers it holds
    return found


def value_matches(expected: Any, got: Any) -> bool:
    if isinstance(expected, dict):
        if "$contains" in expected:
            blob = json.dumps(got, ensure_ascii=False).lower() if got is not None else ""
            return all(str(s).lower() in blob for s in expected["$contains"])
        if "$any_of" in expected:
            return any(value_matches(alt, got) for alt in expected["$any_of"])
        if "$subset" in expected:
            return isinstance(got, dict) and all(
                key in got and value_matches(want, got[key])
                for key, want in expected["$subset"].items()
            )
        return False
    if isinstance(expected, list):
        return isinstance(got, list) and all(
            any(value_matches(e, g) for g in got) for e in expected
        )
    if isinstance(expected, bool) or isinstance(got, bool):
        return expected is got
    if isinstance(expected, int | float) and isinstance(got, int | float | str):
        try:
            return float(got) == float(expected)
        except ValueError:
            return False
    return str(got).strip().lower() == str(expected).strip().lower()


def score_answer(
    task: dict[str, Any], answer: dict[str, Any] | None, candidates: list[str] | None
) -> dict[str, bool]:
    """A tool counts only when it is an offered candidate; arguments need every required one."""
    if not answer:
        return {"tool": False, "args": False}
    offered = candidates is None or task["expected_tool"] in candidates
    tool_ok = answer.get("tool") == task["expected_tool"] and offered
    given = answer.get("arguments") if isinstance(answer.get("arguments"), dict) else {}
    args_ok = tool_ok and all(
        key in given and value_matches(want, given[key])
        for key, want in task["required_args"].items()
    )
    return {"tool": tool_ok, "args": args_ok}


class Ledger:
    """Tokens spent plus tokens reserved by calls in flight, held under the budget."""

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.spent = 0
        self.reserved = 0
        self._lock = threading.Lock()

    def reserve(self, estimate: int) -> bool:
        with self._lock:
            if self.spent + self.reserved + estimate > self.budget:
                return False
            self.reserved += estimate
            return True

    def settle(self, estimate: int, actual: int) -> None:
        with self._lock:
            self.reserved -= estimate
            self.spent += actual


def run_llm(
    selection: dict[str, Any],
    model: str,
    runs: int,
    budget: int,
    workers: int,
    degraded: bool = False,
) -> dict[str, Any]:
    if degraded:
        selection = {**selection, "tools": {n: degrade(e) for n, e in selection["tools"].items()}}
    prompts = {}
    for mode in MODES:
        prompts[mode] = [
            (b, build_prompt(b, selection["tools"])) for b in make_batches(selection, mode)
        ]
    per_run = {
        mode: sum(estimate_tokens(p, len(b["tasks"])) for b, p in items)
        for mode, items in prompts.items()
    }
    estimate = runs * sum(per_run.values())
    print(
        f"estimate: {estimate:,} tokens for {runs} runs (search {per_run['search']:,}, "
        f"full {per_run['full']:,} per run; budget {budget:,})",
        file=sys.stderr,
    )
    if estimate > budget:
        raise SystemExit(
            f"refusing to start: the estimate {estimate:,} exceeds the budget {budget:,}"
        )
    ledger = Ledger(budget)
    spent_by_mode = {m: 0 for m in MODES}
    lock = threading.Lock()

    def work(item: tuple[str, dict[str, Any], str]) -> dict[str, Any]:
        mode, batch, prompt = item
        need = estimate_tokens(prompt, len(batch["tasks"]))
        if not ledger.reserve(need):
            raise SystemExit(
                f"stopping: the next call could pass the budget ({ledger.spent:,} of {budget:,})"
            )
        res: dict[str, Any] = {"tokens": 0, "answers": {}, "error": "not run"}
        try:
            res = call_model(prompt, model)
        finally:
            ledger.settle(need, res["tokens"])
            with lock:
                spent_by_mode[mode] += res["tokens"]
        out = {}
        for task in batch["tasks"]:
            answer = res["answers"].get(task["id"])
            out[task["id"]] = {
                **score_answer(task, answer, batch["candidates"][task["id"]]),
                "chose": (answer or {}).get("tool"),
                "error": res["error"] if answer is None else None,
            }
        return out

    modes_out: dict[str, Any] = {m: {"runs": []} for m in MODES}
    for run in range(1, runs + 1):
        items = [(m, b, p) for m in MODES for b, p in prompts[m]]
        items.sort(key=lambda it: -len(it[2]))  # the big full-mode calls start first
        merged: dict[str, dict[str, Any]] = {m: {} for m in MODES}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for item, result in zip(items, pool.map(work, items), strict=True):
                merged[item[0]].update(result)
        for mode in MODES:
            done = sum(r["args"] for r in merged[mode].values())
            print(f"run {run} {mode}: {done}/{len(merged[mode])} arguments right", file=sys.stderr)
            modes_out[mode]["runs"].append(
                {"run": run, "results": dict(sorted(merged[mode].items()))}
            )
        print(f"  tokens so far: {ledger.spent:,}", file=sys.stderr)
    return {
        "model": model,
        "modes": modes_out,
        "tokens_total": ledger.spent,
        "tokens_by_mode": spent_by_mode,
        "token_budget": budget,
        "degraded": degraded,
    }


# --------------------------------------------------------------------------------- report


def spread(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.mean(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "range": round(max(values) - min(values), 4),
        "stdev": round(statistics.pstdev(values), 4),
    }


def _mode_report(tasks: list[dict[str, Any]], runs: list[dict[str, Any]]) -> dict[str, Any]:
    def rates(subset: list[dict[str, Any]], key: str) -> list[float]:
        ids = [t["id"] for t in subset]
        return [sum(run["results"][i][key] for i in ids) / len(ids) for run in runs]

    right_tool = []
    for run in runs:
        right = [r for r in run["results"].values() if r["tool"]]
        right_tool.append(sum(r["args"] for r in right) / len(right) if right else 0.0)
    hard = [t for t in tasks if t.get("hard")]
    easy = [t for t in tasks if not t.get("hard")]
    categories = sorted({t["hard"] for t in hard})
    flips = sorted(
        t["id"] for t in tasks if len({run["results"][t["id"]]["args"] for run in runs}) > 1
    )
    return {
        "selection_accuracy": spread(rates(tasks, "tool")),
        "argument_accuracy_end_to_end": spread(rates(tasks, "args")),
        "argument_accuracy_given_right_tool": spread(right_tool),
        "near_duplicate_pairs": {
            "selection": spread(rates([t for t in tasks if t["pair"]], "tool")),
            "arguments": spread(rates([t for t in tasks if t["pair"]], "args")),
        },
        "hard_tasks": {
            "selection": spread(rates(hard, "tool")),
            "arguments": spread(rates(hard, "args")),
        },
        "easy_tasks": {
            "selection": spread(rates(easy, "tool")),
            "arguments": spread(rates(easy, "args")),
        },
        "by_hard_category": {
            c: spread(rates([t for t in hard if t["hard"] == c], "args")) for c in categories
        },
        "per_run_selection": [round(x, 4) for x in rates(tasks, "tool")],
        "per_run_arguments": [round(x, 4) for x in rates(tasks, "args")],
        "tasks_that_flip_between_runs": flips,
        "tasks_wrong_in_every_run": sorted(
            t["id"] for t in tasks if not any(run["results"][t["id"]]["args"] for run in runs)
        ),
        "calls_without_an_answer": sum(
            1 for run in runs for r in run["results"].values() if r["error"]
        ),
    }


def build_report(
    selection: dict[str, Any], llm: dict[str, Any], degraded: dict[str, Any] | None = None
) -> dict[str, Any]:
    tasks = load_tasks()
    if selection["tasks_sha256"] != tasks_sha256():
        raise SystemExit("the selection file was made from a different task set")
    report = {
        "model": llm["model"],
        "runs": len(llm["modes"]["search"]["runs"]),
        "tasks": len(tasks),
        "hard_tasks": sum(1 for t in tasks if t.get("hard")),
        "tasks_sha256": selection["tasks_sha256"],
        "catalog_tools": selection["catalog_tools"],
        "selection": selection_numbers(tasks, selection["rows"]),
        "search_mode": _mode_report(tasks, llm["modes"]["search"]["runs"]),
        "full_mode": _mode_report(tasks, llm["modes"]["full"]["runs"]),
        "tokens": {
            "total": llm["tokens_total"],
            "search_mode": llm["tokens_by_mode"]["search"],
            "full_mode": llm["tokens_by_mode"]["full"],
            "budget": llm["token_budget"],
        },
        "measured_on": _git("merge-base", "HEAD", "origin/dev") or _git("rev-parse", "HEAD"),
        "measured_at": _git("show", "-s", "--format=%cs", "HEAD"),
    }
    if degraded:
        report["sensitivity_degraded_descriptions"] = {
            "what": "same tasks and protocol, but every tool shows only the first sentence of its "
            "description and no parameter descriptions",
            "runs": len(degraded["modes"]["search"]["runs"]),
            "tokens": degraded["tokens_total"],
            "search_mode": _mode_report(tasks, degraded["modes"]["search"]["runs"]),
            "full_mode": _mode_report(tasks, degraded["modes"]["full"]["runs"]),
        }
    return report


def _git(*cmd: str) -> str:
    proc = subprocess.run(["git", *cmd], cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603, S607
    return proc.stdout.strip()


def check_selection(selection: dict[str, Any]) -> int:
    """CI part: the committed selection floor still holds (no model involved)."""
    baseline = json.loads(BASELINE.read_text())
    if selection["tasks_sha256"] != baseline["tasks_sha256"]:
        print("the task set changed: re-run the eval and write the baseline", file=sys.stderr)
        return 1
    now = selection_numbers(load_tasks(), selection["rows"])["overall"]
    floor = baseline["selection"]["overall"]["top5"] - CHECK_SLACK_TASKS
    print(
        f"top-1 {now['top1']}/{now['tasks']}  top-5 {now['top5']}/{now['tasks']}  (floor {floor})"
    )
    return 0 if now["top5"] >= floor else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_sel = sub.add_parser("select", help="deterministic part: search_tools top-1 / top-5")
    p_sel.add_argument("--out", type=Path)
    p_sel.add_argument("--floor", action="store_true", help="compare with the committed floor")
    p_llm = sub.add_parser("llm", help="model part: claude -p, search mode and full mode, repeated")
    p_llm.add_argument("--selection", type=Path, required=True)
    p_llm.add_argument("--out", type=Path, required=True)
    p_llm.add_argument("--model", default=MODEL)
    p_llm.add_argument("--runs", type=int, default=RUNS)
    p_llm.add_argument("--token-budget", type=int, default=TOKEN_BUDGET)
    p_llm.add_argument("--workers", type=int, default=4)
    p_llm.add_argument(
        "--degrade",
        action="store_true",
        help="sensitivity check: no parameter descriptions, first sentence of each tool only",
    )
    p_rep = sub.add_parser("report", help="merge both parts into the report")
    p_rep.add_argument("--selection", type=Path, required=True)
    p_rep.add_argument("--llm", type=Path, required=True)
    p_rep.add_argument("--degraded", type=Path, help="llm output of a --degrade run to include")
    p_rep.add_argument("--write-baseline", action="store_true")
    ns = parser.parse_args(argv)
    if ns.cmd == "select":
        sys.path.insert(0, str(ROOT / "src"))
        selection = asyncio.run(run_selection())
        if ns.out:
            ns.out.write_text(json.dumps(selection))
        if ns.floor:
            return check_selection(selection)
        print(json.dumps(selection_numbers(load_tasks(), selection["rows"])["overall"]))
        return 0
    if ns.cmd == "llm":
        selection = json.loads(ns.selection.read_text())
        result = run_llm(
            selection, ns.model, ns.runs, ns.token_budget, ns.workers, degraded=ns.degrade
        )
        ns.out.write_text(json.dumps(result))
        return 0
    report = build_report(
        json.loads(ns.selection.read_text()),
        json.loads(ns.llm.read_text()),
        json.loads(ns.degraded.read_text()) if ns.degraded else None,
    )
    text = json.dumps(report, indent=2) + "\n"
    if ns.write_baseline:
        BASELINE.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
