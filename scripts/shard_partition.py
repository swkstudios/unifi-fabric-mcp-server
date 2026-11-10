#!/usr/bin/env python3
"""Partition a test run into shards and prove the shards cover it exactly once.

Pure, standard-library-only functions shared by the pytest plugin that selects a shard
(``tests/_sharding.py``, node IDs), the aggregate CI job that checks the shards, and any
other suite that must split a list of case IDs and prove the split (the scrub oracle's
case IDs use the same ``assign`` and ``verify``).

* ``assign(units, weights, n)``: unit -> shard (1..n). Units named in ``weights`` are the
  heavy ones, placed longest first onto the lightest shard (ties: lower shard number, and
  units with equal weight by name). Every other unit goes by
  ``int(sha256("unifi-shard-v1:" + unit), 16) % n``, so adding or removing one unit moves
  only that unit. The result depends only on the inputs.
* ``verify(full, shards, executed, ...)``: every check of the aggregate job, returning a
  list of error strings (empty means the proof holds). It lists missing and extra IDs.

Run as a script, ``verify`` reads the anchor list (a plain ``pytest --collect-only -q``),
the shard report files and the coverage files, and exits 1 on any defect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

SALT = "unifi-shard-v1:"
REPORT_FORMAT = 1
#: Final outcomes that do not fail the proof; anything else (failed, error, ...) does.
OK_OUTCOMES = frozenset({"passed", "skipped", "xfailed", "xpassed"})
#: Longest list of missing / extra / duplicated IDs written into one error message.
LISTED = 20


def parse_shard(text: str) -> tuple[int, int]:
    """``"K/N"`` -> ``(K, N)`` with 1 <= K <= N; ``ValueError`` otherwise."""
    k_text, sep, n_text = text.partition("/")
    if not (
        sep and k_text.isascii() and k_text.isdigit() and n_text.isascii() and n_text.isdigit()
    ):
        raise ValueError(f"shard {text!r} is not K/N")
    k, n = int(k_text), int(n_text)
    if not 1 <= k <= n:
        raise ValueError(f"shard {text!r} needs 1 <= K <= N")
    return k, n


def hash_shard(unit: str, n: int) -> int:
    """The 1-based shard a light unit belongs to."""
    return int(hashlib.sha256((SALT + unit).encode()).hexdigest(), 16) % n + 1


def assign(units: Iterable[str], weights: Mapping[str, float], n: int) -> dict[str, int]:
    """Map each distinct unit to a shard number in ``1..n`` (see the module docstring)."""
    if n < 1:
        raise ValueError("shard count must be at least 1")
    distinct = sorted(set(units))
    heavy = sorted((u for u in distinct if u in weights), key=lambda u: (-weights[u], u))
    load = [0.0] * n
    placed: dict[str, int] = {}
    for unit in heavy:
        index = min(range(n), key=lambda i: (load[i], i))
        load[index] += weights[unit]
        placed[unit] = index + 1
    for unit in distinct:
        if unit not in placed:
            placed[unit] = hash_shard(unit, n)
    return placed


def ids_digest(ids: Iterable[str]) -> str:
    """sha256 of the sorted, newline-joined ID list (the full pre-selection digest)."""
    return hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()


def _listing(label: str, ids: Iterable[str]) -> str:
    ordered = sorted(ids)
    shown = ", ".join(ordered[:LISTED])
    more = f" (+{len(ordered) - LISTED} more)" if len(ordered) > LISTED else ""
    return f"{label} {len(ordered)}: {shown}{more}"


def check_needs(needs: Mapping[str, Any], required: Iterable[str]) -> list[str]:
    """Check 1: every required job in ``toJson(needs)`` reported ``success``.

    A missing job, a ``skipped``/``cancelled``/``failure`` result and a malformed entry
    all fail."""
    errors = []
    for job in sorted(set(required)):
        entry = needs.get(job)
        result = entry.get("result") if isinstance(entry, Mapping) else None
        if result != "success":
            errors.append(f"needs.{job}.result is {result!r}, not 'success'")
    return errors


def _attempt(value: Any) -> int | None:
    text = str(value)
    return int(text) if text.isascii() and text.isdigit() else None


def select_reports(
    reports: Sequence[Mapping[str, Any]], *, suite: str, run: str
) -> tuple[list[Mapping[str, Any]], list[str]]:
    """Bind the reports to this run: only reports of ``suite`` and ``run`` count, and only
    the newest ``attempt`` per shard. Anything else is rejected with an error (a stale
    attempt of a shard is dropped silently, because a re-run replaces it)."""
    errors: list[str] = []
    newest: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for report in reports:
        label = f"report of shard {report.get('k')!r}"
        if report.get("suite") != suite:
            errors.append(f"{label} is for suite {report.get('suite')!r}, not {suite!r}")
            continue
        if str(report.get("run")) != str(run):
            errors.append(f"{label} is from run {report.get('run')!r}, not {run!r}")
            continue
        attempt = _attempt(report.get("attempt"))
        if attempt is None:
            errors.append(f"{label} has no run attempt")
            continue
        key = repr(report.get("k"))
        current = newest.get(key)
        if current is not None and current[0] == attempt:
            errors.append(f"shard {report.get('k')!r} has two reports for attempt {attempt}")
        elif current is None or attempt > current[0]:
            newest[key] = (attempt, report)
    return [r for _, r in newest.values()], errors


def totals(reports: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Outcome counts summed over all reports (``passed``, ``skipped``, ``xfailed``,
    ``failed``, ...) and ``total``."""
    counts: Counter[str] = Counter()
    for report in reports:
        counts.update(str(o) for o in report.get("outcomes", {}).values())
    return {**dict(sorted(counts.items())), "total": sum(counts.values())}


def verify(
    full: Sequence[str],
    reports: Sequence[Mapping[str, Any]],
    *,
    n: int,
    suite: str,
    run: str,
    commit: str | None = None,
    coverage_files: Sequence[str] | None = None,
    require_identity: bool = False,
    anchor_identity: Mapping[str, Any] | None = None,
) -> list[str]:
    """Checks 2-9 of the aggregate job; the list of defects, empty when the proof holds.

    ``full`` is the independent anchor list (plain collection, no shard). ``n`` must come
    from outside the reports (the ``TEST_SHARDS`` constant), never from them. Each report
    carries ``suite``, ``k``, ``n``, ``run``, ``attempt``, ``commit``, ``full_sha256``,
    ``selected``, ``groups`` and the final ``outcomes`` per executed ID; see
    ``select_reports`` for which reports count. ``coverage_files`` (when given) are the
    coverage data files found; there must be exactly ``n``. ``require_identity`` (the
    ``test-locked`` suite) demands that the shards and ``anchor_identity`` (the record
    ``scripts/env_identity.py record`` writes) carry one equal environment identity and
    that none of them saw a difference from requirements.lock."""
    # 2. only this suite's and run's newest attempts; exactly N, K = 1..N once each.
    shards, errors = select_reports(reports, suite=suite, run=run)
    numbers = Counter(r.get("k") for r in shards)
    if len(shards) != n:
        errors.append(f"expected {n} shard reports, found {len(shards)}")
    for k in range(1, n + 1):
        if numbers.get(k, 0) != 1:
            errors.append(f"shard {k}/{n} appears {numbers.get(k, 0)} times, not once")
    for odd in sorted((k for k in numbers if not isinstance(k, int) or not 1 <= k <= n), key=str):
        errors.append(f"unexpected shard number {odd!r}")
    wrong_n = sorted(str(r.get("k")) for r in shards if r.get("n") != n)
    if wrong_n:
        errors.append(f"shards {', '.join(wrong_n)} report an n other than {n}")
    if commit is None:
        seen = {r.get("commit") for r in shards}
        if len(seen) > 1:
            errors.append(f"shard reports disagree on commit: {sorted(map(str, seen))}")
    else:
        wrong = sorted(str(r.get("k")) for r in shards if r.get("commit") != commit)
        if wrong:
            errors.append(f"shards {', '.join(wrong)} report a commit other than {commit}")

    # 3. every report's full-list hash equals the anchor's.
    duplicate_full = [i for i, c in Counter(full).items() if c > 1]
    if duplicate_full:
        errors.append(_listing("duplicate ids in the anchor list", duplicate_full))
    anchor = ids_digest(full)
    for report in shards:
        if report.get("full_sha256") != anchor:
            errors.append(f"shard {report.get('k')}: full-list hash differs from the anchor list")

    # 4. non-empty, pairwise disjoint, union equals the anchor list.
    union: set[str] = set()
    owner: dict[str, int] = {}
    for report in shards:
        owner_k: Any = report.get("k")
        selected = list(report.get("selected", ()))
        if not selected:
            errors.append(f"shard {owner_k} selected nothing")
        repeated = [i for i, c in Counter(selected).items() if c > 1]
        if repeated:
            errors.append(_listing(f"shard {owner_k} lists ids more than once:", repeated))
        overlap = {i for i in set(selected) if i in owner}
        if overlap:
            errors.append(_listing(f"shard {owner_k} repeats ids of another shard:", overlap))
        for i in selected:
            owner.setdefault(i, owner_k)
        union.update(selected)
    anchor_set = set(full)
    if union != anchor_set:
        if anchor_set - union:
            errors.append(_listing("ids missing from every shard:", anchor_set - union))
        if union - anchor_set:
            errors.append(_listing("ids selected but not in the anchor list:", union - anchor_set))

    # 5. executed == selected in every shard; no failed or error outcome.
    for report in shards:
        label = report.get("k")
        chosen = set(report.get("selected", ()))
        outcomes = report.get("outcomes", {})
        ran = set(outcomes)
        if chosen - ran:
            errors.append(_listing(f"shard {label}: selected ids with no outcome:", chosen - ran))
        if ran - chosen:
            errors.append(
                _listing(f"shard {label}: executed ids outside the selection:", ran - chosen)
            )
        failed = [i for i, o in outcomes.items() if o not in OK_OUTCOMES]
        if failed:
            errors.append(_listing(f"shard {label}: ids that did not pass or skip:", failed))

    # 6. exactly N coverage data files.
    if coverage_files is not None and len(coverage_files) != n:
        errors.append(f"expected {n} coverage data files, found {len(coverage_files)}")

    # 7. every unit stays whole: no xdist_group name in two shards.
    homes: dict[str, set[Any]] = {}
    for report in shards:
        for group in report.get("groups", ()):
            homes.setdefault(str(group), set()).add(report.get("k"))
    split = sorted(g for g, ks in homes.items() if len(ks) > 1)
    if split:
        errors.append(_listing("xdist_group names that span two shards:", split))

    # 8. one environment identity everywhere (test-locked), equal to the lock.
    if require_identity:
        anchor_value = anchor_identity.get("identity") if anchor_identity else None
        if not anchor_value:
            errors.append("the anchor carries no environment identity")
        values = {str(r.get("k")): r.get("identity") for r in shards}
        absent = sorted(k for k, v in values.items() if not isinstance(v, Mapping) or not v)
        if absent:
            errors.append(f"shards {', '.join(absent)} carry no environment identity")
        found = {json.dumps(v, sort_keys=True) for v in values.values() if v}
        if anchor_value:
            found.add(json.dumps(anchor_value, sort_keys=True))
        if len(found) > 1:
            errors.append(
                "environment identity differs between shards or the anchor: "
                + "; ".join(sorted(found))
            )
        for report in shards:
            lock_errors = report.get("lock_errors")
            if not isinstance(lock_errors, list):
                errors.append(
                    f"shard {report.get('k')} did not check its environment against the lock"
                )
            elif lock_errors:
                errors.append(
                    _listing(f"shard {report.get('k')} differs from the lock:", lock_errors)
                )
        anchor_lock = anchor_identity.get("lock_errors") if anchor_identity else None
        if not isinstance(anchor_lock, list):
            errors.append("the anchor did not check its environment against the lock")
        elif anchor_lock:
            errors.append(_listing("the anchor differs from the lock:", anchor_lock))
    return errors


def parse_collect_only(text: str) -> list[str]:
    """Node IDs from ``pytest --collect-only -q`` output (lines holding ``::``)."""
    return [
        line.strip()
        for line in text.splitlines()
        if "::" in line and not line.startswith((" ", "=", "-"))
    ]


def proof(
    full: Sequence[str],
    shards: Sequence[Mapping[str, Any]],
    n: int,
    commit: str | None,
    suite: str,
    run: str,
    errors: Sequence[str] = (),
) -> dict:
    """The per-run proof record: counts, summed outcome totals, hashes and identities.

    ``ok`` is true only when ``errors`` (the defects the verify step found) is empty, so a
    consumer such as ``scripts/release_evidence.py`` need not re-derive the verdict.
    """
    ordered = sorted(shards, key=lambda r: str(r.get("k")))
    return {
        "suite": suite,
        "run": run,
        "n": n,
        "commit": commit,
        "ok": not errors,
        "errors": list(errors),
        "anchor_count": len(full),
        "anchor_sha256": ids_digest(full),
        "totals": totals(shards),
        "shards": [
            {
                "k": r.get("k"),
                "attempt": r.get("attempt"),
                "selected": len(r.get("selected", ())),
                "full_sha256": r.get("full_sha256"),
                "identity": r.get("identity"),
                "install_seconds": r.get("install_seconds"),
                "totals": totals([r]),
            }
            for r in ordered
        ],
    }


# -- shard artifacts (the aggregate job's download) ----------------------------------------

#: Files every shard artifact carries.
ARTIFACT_FILES = ("report.json", ".coverage")


def select_artifacts(
    names: Iterable[str], *, prefix: str, run: str, n: int
) -> tuple[dict[int, str], list[str], list[str]]:
    """Choose one artifact per shard from the names ``<prefix>-<K>-<run>-<attempt>``.

    Returns ``(chosen, stale, errors)``: ``chosen`` maps K (1..n) to the newest attempt's
    name, ``stale`` lists the older attempts it replaced (a re-run of a shard), and
    ``errors`` lists every name of another shape, another run or a shard outside 1..n,
    two artifacts of one attempt, and every K with no artifact."""
    pattern = re.compile(re.escape(prefix) + r"-([1-9][0-9]*)-([0-9]+)-([1-9][0-9]*)")
    errors: list[str] = []
    newest: dict[int, tuple[int, str]] = {}
    stale: list[str] = []
    for name in sorted(names):
        match = pattern.fullmatch(name)
        if match is None:
            errors.append(f"unexpected artifact {name!r} (not {prefix}-<K>-<run>-<attempt>)")
            continue
        k, artifact_run, attempt = int(match[1]), match[2], int(match[3])
        if artifact_run != str(run):
            errors.append(f"artifact {name} is from run {artifact_run}, not {run}")
            continue
        if not 1 <= k <= n:
            errors.append(f"artifact {name} is for shard {k}, outside 1..{n}")
            continue
        current = newest.get(k)
        if current is not None and current[0] == attempt:
            errors.append(f"shard {k} has two artifacts for attempt {attempt}")
        elif current is None or attempt > current[0]:
            if current is not None:
                stale.append(current[1])
            newest[k] = (attempt, name)
        else:
            stale.append(name)
    for k in range(1, n + 1):
        if k not in newest:
            errors.append(f"shard {k}/{n} has no artifact")
    return {k: name for k, (_, name) in sorted(newest.items())}, sorted(stale), errors


def summary_markdown(record: Mapping[str, Any], coverage: Mapping[str, Any] | None) -> str:
    """The step-summary table of one aggregate run."""
    t = record.get("totals", {})
    lines = [
        f"### Shard proof: {record.get('suite')} ({record.get('n')} shards)",
        "",
        f"Anchor {record.get('anchor_count')} ids, sha256 `{record.get('anchor_sha256')}`;"
        f" totals {', '.join(f'{k} {v}' for k, v in t.items())}.",
    ]
    if coverage:
        lines.append(
            f"Combined coverage {coverage['percent']:.4f}% of {coverage['statements']}"
            f" statements, {coverage['missed']} missed."
        )
    lines += [
        "",
        "| Shard | Attempt | Selected | Passed | Skipped | Install s |",
        "|---|---|---|---|---|---|",
    ]
    for shard in record.get("shards", []):
        st = shard.get("totals", {})
        install = shard.get("install_seconds")
        lines.append(
            f"| {shard.get('k')} | {shard.get('attempt')} | {shard.get('selected')} |"
            f" {st.get('passed', 0)} | {st.get('skipped', 0)} |"
            f" {'-' if install is None else install} |"
        )
    return "\n".join(lines) + "\n"


# -- scrub oracle chunk evidence (used by shard_ci.sh scrub-aggregate) ---------------------

#: A scrub-oracle chunk: ``tests/test_secret_scrub_oracle.py::test_slow[<chunk>]``.
SCRUB_CHUNK = re.compile(r"tests/test_secret_scrub_oracle\.py::test_slow\[([0-9]+)\]")
#: One chunk's evidence file, as ``run_chunk`` writes it: ``slow-<seed>.json``.
SCRUB_EVIDENCE = re.compile(r"slow-([0-9]+)\.json")


def scrub_evidence(
    shards: Mapping[int, tuple[Mapping[str, Any], Mapping[str, Mapping[str, Any]]]],
) -> list[str]:
    """Every executed chunk left exactly one evidence file, and nothing else did.

    ``shards`` maps K to ``(report, evidence)``: the shard report and the evidence files
    of that shard by file name. In each shard the number of ``slow-<seed>.json`` files
    equals the number of chunks it ran, every file names its own seed and the ``slow``
    corpus, and no seed appears in two shards. Returns the defects (empty: it holds)."""
    errors: list[str] = []
    seen: dict[int, int] = {}
    for k in sorted(shards):
        report, files = shards[k]
        outcomes = report.get("outcomes", {})
        chunks = sorted(i for i in outcomes if SCRUB_CHUNK.fullmatch(i))
        passed = [i for i in chunks if outcomes[i] == "passed"]
        if passed != chunks:
            errors.append(
                _listing(f"shard {k}: chunks that did not pass:", set(chunks) - set(passed))
            )
        seeds: list[int] = []
        for name in sorted(files):
            match = SCRUB_EVIDENCE.fullmatch(name)
            data = files[name]
            if match is None:
                errors.append(f"shard {k}: unexpected evidence file {name!r}")
                continue
            seed = int(match[1])
            if data.get("corpus") != "slow" or data.get("seed") != seed:
                errors.append(f"shard {k}: {name} does not hold the slow corpus seed {seed}")
                continue
            seeds.append(seed)
            if seed in seen:
                errors.append(f"seed {seed} has evidence from shards {seen[seed]} and {k}")
            else:
                seen[seed] = k
        if len(seeds) != len(chunks):
            errors.append(
                f"shard {k} ran {len(chunks)} chunks but left {len(seeds)} evidence files"
            )
    return errors


def junit_passed(text: str) -> tuple[list[str], list[str]]:
    """``(passed, other)`` test case names of a JUnit XML report: a skipped, failed or
    errored case is ``other``, so "ran and passed" can be required, not just "exit 0"."""
    import xml.etree.ElementTree as ET  # noqa: S405 - our own pytest output

    passed: list[str] = []
    other: list[str] = []
    for case in ET.fromstring(text).iter("testcase"):  # noqa: S314
        name = f"{case.get('classname')}::{case.get('name')}"
        if any(case.find(tag) is not None for tag in ("skipped", "failure", "error")):
            other.append(name)
        else:
            passed.append(name)
    return passed, other


# -- coverage data checks (used by run_full_suite.sh --combine) ----------------------------


def coverage_has_data(path: str | Path) -> bool:
    """True when a ``.coverage`` data file holds measured lines or arcs."""
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            for table in ("line_bits", "arc"):
                try:
                    if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():  # noqa: S608
                        return True
                except sqlite3.OperationalError:
                    continue
    except sqlite3.Error:
        return False
    return False


def coverage_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    """Combined percent, statements and missed from ``coverage json`` output."""
    t = report["totals"]
    summary: dict[str, Any] = {
        "percent": t["percent_covered"],
        "statements": t["num_statements"],
        "missed": t["missing_lines"],
        "covered": t["covered_lines"],
    }
    for key in ("num_branches", "missing_branches", "covered_branches"):
        if key in t:
            summary[key] = t[key]
    return summary


def _main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify", help="check shard reports against the anchor list")
    check.add_argument("--anchor", required=True, type=Path, help="pytest --collect-only -q output")
    check.add_argument("--reports", required=True, type=Path, help="directory of shard reports")
    check.add_argument(
        "--shards",
        required=True,
        type=int,
        help="N, from the TEST_SHARDS constant (not the reports)",
    )
    check.add_argument("--job-total", type=int, help="strategy.job-total; must equal --shards")
    check.add_argument("--suite", required=True, help="suite name the reports must carry")
    check.add_argument("--run-id", required=True, help="GITHUB_RUN_ID the reports must carry")
    check.add_argument("--commit", help="expected commit (default: reports must agree)")
    check.add_argument("--coverage", type=Path, help="directory searched for .coverage files")
    check.add_argument("--needs", type=Path, help="toJson(needs) file")
    check.add_argument("--require", default="", help="comma-separated jobs that must be success")
    check.add_argument("--locked", action="store_true", help="require one locked environment")
    check.add_argument("--anchor-identity", type=Path, help="env_identity.py record output")
    check.add_argument("--proof", type=Path, help="write the proof record here")
    data = sub.add_parser("coverage-data", help="fail when a .coverage file has no measured data")
    data.add_argument("files", nargs="+", type=Path)
    summary = sub.add_parser("coverage-summary", help="write the combined summary JSON")
    summary.add_argument("source", type=Path, help="coverage json output")
    summary.add_argument("out", type=Path)
    pick = sub.add_parser("select-artifacts", help="keep this run's newest artifact per shard")
    pick.add_argument("--root", required=True, type=Path, help="one directory per artifact")
    pick.add_argument("--prefix", required=True, help="artifact name prefix, e.g. test-shard")
    pick.add_argument("--run-id", required=True, help="GITHUB_RUN_ID the artifacts must carry")
    pick.add_argument("--shards", required=True, type=int, help="N, from the TEST_SHARDS constant")
    pick.add_argument("--out", required=True, type=Path, help="copies the chosen ones to OUT/K")
    pick.add_argument(
        "--files",
        default=",".join(ARTIFACT_FILES),
        help="comma-separated files every chosen artifact must hold (default: %(default)s)",
    )
    scrub = sub.add_parser(
        "scrub-evidence", help="check the chunk evidence of every shard and merge it"
    )
    scrub.add_argument("--shards-dir", required=True, type=Path, help="OUT of select-artifacts")
    scrub.add_argument("--shards", required=True, type=int, help="N, from the constant")
    scrub.add_argument("--out", required=True, type=Path, help="merged evidence directory")
    junit = sub.add_parser("junit-passed", help="require exactly COUNT passed cases")
    junit.add_argument("report", type=Path)
    junit.add_argument("--count", required=True, type=int)
    table = sub.add_parser("summary", help="markdown summary of a proof record")
    table.add_argument("proof", type=Path)
    table.add_argument("coverage", type=Path, nargs="?")
    args = parser.parse_args(argv)

    if args.command == "select-artifacts":
        names = [p.name for p in sorted(args.root.iterdir())] if args.root.is_dir() else []
        chosen, stale, errors = select_artifacts(
            names, prefix=args.prefix, run=args.run_id, n=args.shards
        )
        required = [f for f in args.files.split(",") if f]
        for name in chosen.values():
            missing = [f for f in required if not (args.root / name / f).is_file()]
            if missing:
                errors.append(f"artifact {name} has no {', '.join(missing)}")
        for error in errors:
            print(f"shard artifacts: {error}", file=sys.stderr)
        if errors:
            return 1
        args.out.mkdir(parents=True, exist_ok=False)
        for k, name in chosen.items():
            shutil.copytree(args.root / name, args.out / str(k))
        for name in stale:
            print(f"shard artifacts: {name} replaced by a newer attempt")
        print(f"shard artifacts: {len(chosen)} of {args.shards} shards, run {args.run_id}")
        return 0
    if args.command == "scrub-evidence":
        shards: dict[int, tuple[dict[str, Any], dict[str, dict[str, Any]]]] = {}
        errors = []
        for k in range(1, args.shards + 1):
            folder = args.shards_dir / str(k)
            report_path = folder / "report.json"
            if not report_path.is_file():
                errors.append(f"shard {k} has no report")
                continue
            evidence = folder / "evidence"
            files = (
                {p.name: json.loads(p.read_text()) for p in sorted(evidence.iterdir())}
                if evidence.is_dir()
                else {}
            )
            shards[k] = (json.loads(report_path.read_text()), files)
        extra = (
            sorted(
                p.name
                for p in args.shards_dir.iterdir()
                if p.name not in map(str, range(1, args.shards + 1))
            )
            if args.shards_dir.is_dir()
            else []
        )
        if extra:
            errors.append(f"unexpected shard directories {extra}")
        errors += scrub_evidence(shards)
        for error in errors:
            print(f"scrub evidence: {error}", file=sys.stderr)
        if errors:
            return 1
        args.out.mkdir(parents=True, exist_ok=False)
        count = 0
        for k in sorted(shards):
            for name, data in shards[k][1].items():
                (args.out / name).write_text(json.dumps(data))
                count += 1
        print(f"scrub evidence: {count} chunk files from {len(shards)} shards, one per chunk")
        return 0
    if args.command == "junit-passed":
        passed, other = junit_passed(args.report.read_text())
        if other or len(passed) != args.count:
            print(
                f"junit: {len(passed)} passed (need {args.count}); not passed: {other}",
                file=sys.stderr,
            )
            return 1
        print(f"junit: {len(passed)} passed: {', '.join(passed)}")
        return 0
    if args.command == "summary":
        record = json.loads(args.proof.read_text())
        coverage = None
        if args.coverage is not None and args.coverage.is_file():
            coverage = json.loads(args.coverage.read_text())
        sys.stdout.write(summary_markdown(record, coverage))
        return 0

    if args.command == "coverage-data":
        empty = [str(p) for p in args.files if not coverage_has_data(p)]
        for path in empty:
            print(f"coverage data: {path} has no measured data", file=sys.stderr)
        return 1 if empty else 0
    if args.command == "coverage-summary":
        result = coverage_summary(json.loads(args.source.read_text()))
        args.out.write_text(json.dumps(result, indent=1))
        print(
            f"coverage summary: {result['percent']:.4f}% of {result['statements']} statements,"
            f" {result['missed']} missed"
        )
        return 0

    errors: list[str] = []
    if args.job_total is not None and args.job_total != args.shards:
        errors.append(f"the matrix has {args.job_total} jobs but N is {args.shards}")
    if args.needs:
        errors += check_needs(
            json.loads(args.needs.read_text()), filter(None, args.require.split(","))
        )
    full = parse_collect_only(args.anchor.read_text())
    if not full:
        errors.append("the anchor list is empty")
    reports = [json.loads(p.read_text()) for p in sorted(args.reports.rglob("*.json"))]
    reports = [r for r in reports if isinstance(r, dict) and r.get("format") == REPORT_FORMAT]
    coverage = None
    if args.coverage:
        coverage = [str(p) for p in sorted(args.coverage.rglob(".coverage")) if p.is_file()]
    anchor_identity = json.loads(args.anchor_identity.read_text()) if args.anchor_identity else None
    errors += verify(
        full,
        reports,
        n=args.shards,
        suite=args.suite,
        run=args.run_id,
        commit=args.commit,
        coverage_files=coverage,
        require_identity=args.locked,
        anchor_identity=anchor_identity,
    )
    if args.proof:
        kept, _ = select_reports(reports, suite=args.suite, run=args.run_id)
        record = proof(full, kept, args.shards, args.commit, args.suite, args.run_id, errors)
        args.proof.write_text(json.dumps(record, indent=1))
    for error in errors:
        print(f"shard proof: {error}", file=sys.stderr)
    if not errors:
        kept, _ = select_reports(reports, suite=args.suite, run=args.run_id)
        counts = ", ".join(f"{k} {v}" for k, v in totals(kept).items())
        print(
            f"shard proof: {len(full)} ids, {args.shards} shards, disjoint, complete,"
            f" all executed ({counts})"
        )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
