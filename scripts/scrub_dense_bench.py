"""Dense 51 KB echo-body CPU benchmark: scrub() and scrub_bytes(), cold, per core.

Use (repo root, project venv):
    python scripts/scrub_dense_bench.py --core base=PATH --core candidate=PATH [--runs 7]
        [--fresh] [--body echo|closed]

``--fresh`` runs every sample in a NEW interpreter (nothing of an earlier sample is
left: the form tables are warmed there on a tiny escaped text, every memo is emptied,
then one call is timed); samples still alternate across cores. ``--body closed`` is the
second dense body (R-433 M-2): the echo body without its three 64-deep ``%25`` chains,
so every region reaches its full closure (no G5 bound) and the time is decoding, not
fail-closed masking.

Each core file is loaded as its own module. Every timed call starts COLD: every
result/model memo the core keeps is emptied first, so a sample measures one full scrub
(the single non-dedupable call PERF-V6 is about), never a cache hit. The per-secret
form tables are warmed once beforehand in every core alike (they depend only on the
configured secrets, not on the text). Samples are interleaved across cores. Prints one
JSON object: per core and method the process-time samples, their median and min, and
the ratio of each later core's median to the first core's.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class _Leak:
    """``tests.test_secret_leak_invariant``, imported on first use (a fresh-process
    sample never imports it: the body and secrets reach it in a file)."""

    def __getattr__(self, name: str):
        from tests import test_secret_leak_invariant as module

        return getattr(module, name)


leak = _Leak()


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(f"scrub_core_{name}", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def cold(module) -> None:
    """Empty every text-keyed memo a core may keep (absent ones are skipped)."""
    for name in ("_memo_clear", "_clear_models", "_clear_text_memos"):
        clear = getattr(module, name, None)
        if callable(clear):
            clear()
    for name in ("_cached_models",):
        cached = getattr(module, name, None)
        if hasattr(cached, "cache_clear"):
            cached.cache_clear()


def dense_body(name: str) -> str:
    """``echo``: the 51,438-character ``_echo_body(403)``; ``closed``: the same body
    without the 64-deep ``%25`` chains (every region inside the D and N bounds)."""
    return leak._echo_body(403) if name == "echo" else leak._closed_echo_body(403)


def sample(path: str, method: str, payload: str) -> None:
    """One fresh-process sample: print the CPU seconds of one cold call. The body and
    the (synthetic) secrets come from ``payload``, written by the parent, so a sample
    imports only the core under test."""
    module = load("sample", path)
    inputs = json.loads(Path(payload).read_text())
    body, secrets = inputs["body"], tuple(inputs["secrets"])
    data = body if method == "scrub" else body.encode()
    warm = "warm %41 &amp; \\x41"
    getattr(module, method)(warm if method == "scrub" else warm.encode(), secrets)
    cold(module)
    started = time.process_time()
    out = getattr(module, method)(data, secrets)
    elapsed = time.process_time() - started
    text = out if isinstance(out, str) else out.decode("latin-1")
    print(json.dumps({"cpu": elapsed, "kept": len(text) - 3 * text.count("***")}))


def fresh(cores: dict[str, str], methods: tuple[str, ...], runs: int, body: str) -> dict:
    script = str(Path(__file__).resolve())
    samples: dict = {name: {method: [] for method in methods} for name in cores}
    kept: dict = {name: {} for name in cores}
    with tempfile.TemporaryDirectory(prefix="scrub-bench-") as directory:
        payload = Path(directory) / "inputs.json"
        payload.write_text(json.dumps({"body": body, "secrets": list(leak.CONFIGURED)}))
        payload.chmod(0o600)
        for _ in range(runs):
            for method in methods:
                for name, path in cores.items():
                    done = subprocess.run(  # noqa: S603 - this script, local paths
                        [sys.executable, script, "--sample", path, method, str(payload)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    row = json.loads(done.stdout)
                    samples[name][method].append(row["cpu"])
                    kept[name][method] = row["kept"]
    return {"samples": samples, "kept": kept}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", action="append", default=[], help="NAME=PATH")
    parser.add_argument("--runs", type=int, default=11)
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--body", choices=("echo", "closed"), default="echo")
    parser.add_argument("--sample", nargs=3, metavar=("PATH", "METHOD", "PAYLOAD"))
    args = parser.parse_args()
    if args.sample:
        sample(*args.sample)
        return 0
    if not args.core:
        parser.error("--core is required")
    body = dense_body(args.body)
    inputs = {"scrub": body, "scrub_bytes": body.encode()}
    cores = dict(item.split("=", 1) for item in args.core)
    if args.fresh:
        report: dict = {"body": args.body, "body_chars": len(body), "runs": args.runs}
        report["load_start"] = os.getloadavg()
        measured = fresh(cores, tuple(inputs), args.runs, body)
        report["cores"] = {
            name: {
                method: {
                    "median": statistics.median(values),
                    "min": min(values),
                    "kept_chars": measured["kept"][name][method],
                    "samples": values,
                }
                for method, values in per.items()
            }
            for name, per in measured["samples"].items()
        }
        names = list(cores)
        if len(names) >= 2:
            report["ratio_vs_" + names[0]] = {
                other: {
                    method: report["cores"][other][method]["median"]
                    / report["cores"][names[0]][method]["median"]
                    for method in inputs
                }
                for other in names[1:]
            }
        report["load_end"] = os.getloadavg()
        print(json.dumps(report, indent=1))
        return 0
    modules = {name: load(name, path) for name, path in cores.items()}
    report = {
        "body": args.body,
        "body_chars": len(body),
        "runs": args.runs,
        "load_start": os.getloadavg(),
        "cores": {},
    }
    for module in modules.values():
        for method, data in inputs.items():  # warm the per-secret form tables
            getattr(module, method)(data, leak.CONFIGURED)
    samples: dict = {name: {method: [] for method in inputs} for name in modules}
    outputs: dict = {}
    # Interleaved: every round times each core once per method, so host-load drift
    # affects every core alike.
    for _ in range(args.runs):
        for method, data in inputs.items():
            for name, module in modules.items():
                cold(module)
                started = time.process_time()
                out = getattr(module, method)(data, leak.CONFIGURED)
                samples[name][method].append(time.process_time() - started)
                if outputs.setdefault((name, method), out) != out:
                    raise SystemExit(f"{name} {method}: output changed between runs")
    for name in modules:
        report["cores"][name] = {
            method: {
                "median": statistics.median(values),
                "min": min(values),
                "samples": values,
            }
            for method, values in samples[name].items()
        }
    names = list(modules)
    if len(names) >= 2:
        base = names[0]
        report["ratio_vs_" + base] = {
            other: {
                method: report["cores"][other][method]["median"]
                / report["cores"][base][method]["median"]
                for method in inputs
            }
            for other in names[1:]
        }
    report["load_end"] = os.getloadavg()
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
