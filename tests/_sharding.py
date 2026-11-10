"""``--shard K/N``: run one deterministic slice of the collected test items.

Inert unless ``--shard`` is given. The selection is a pure function of the collected IDs,
the committed heavy list (``tests/shard_heavy_units.json``) and a fixed salt
(``scripts/shard_partition.py``). The unit of assignment is the ``xdist_group`` name when
an item has one (a group never splits), else the item's node ID.

The hook runs last, after the ``-m`` and ``-k`` deselection, so its input is exactly the
item list an unsharded run would execute. Items of other shards go through
``pytest_deselected``. With ``--shard-report PATH`` the run writes a JSON report: commit,
run, K, N, the sha256 of the sorted full pre-selection ID list, the selected IDs and the
final outcome per executed ID (read where results arrive: the xdist controller, or the
single process). ``scripts/shard_partition.py verify`` checks the reports of all shards
against an independent plain collection.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
HEAVY_UNITS = Path(__file__).with_name("shard_heavy_units.json")
_PARTITION_PATH = ROOT / "scripts" / "shard_partition.py"
_IDENTITY_PATH = ROOT / "scripts" / "env_identity.py"


def partition():
    """The shared ``scripts/shard_partition.py`` module (loaded once, by path)."""
    module = sys.modules.get("shard_partition")
    if module is None:
        spec = importlib.util.spec_from_file_location("shard_partition", _PARTITION_PATH)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules["shard_partition"] = module
        spec.loader.exec_module(module)
    return module


def env_identity():
    """The shared ``scripts/env_identity.py`` module (loaded once, by path)."""
    module = sys.modules.get("env_identity")
    if module is None:
        spec = importlib.util.spec_from_file_location("env_identity", _IDENTITY_PATH)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules["env_identity"] = module
        spec.loader.exec_module(module)
    return module


def heavy_weights(path: Path = HEAVY_UNITS) -> dict[str, float]:
    """Unit -> measured seconds for the committed heavy units."""
    data = json.loads(path.read_text())
    return {str(unit): float(seconds) for unit, seconds in data["units"].items()}


def _group_names(item: pytest.Item) -> list[str]:
    """The ``xdist_group`` names of an item, as pytest-xdist's loadgroup reads them."""
    names = set()
    for mark in item.iter_markers("xdist_group"):
        names.add(str(mark.args[0] if mark.args else mark.kwargs.get("name", "default")))
    return sorted(names)


def canonical_id(item: pytest.Item) -> str:
    """The item's node ID without the ``@group`` suffix loadgroup appends to workers' IDs,
    so a sharded worker and a plain collection name every test the same way."""
    names = _group_names(item)
    nodeid = item.nodeid
    suffix = "@" + "_".join(names)
    if names and nodeid.endswith(suffix):
        return nodeid[: -len(suffix)]
    return nodeid


def unit_of(item: pytest.Item) -> str:
    """The assignment unit: the ``xdist_group`` name (joined as xdist joins several), else
    the node ID."""
    names = _group_names(item)
    return "_".join(names) if names else canonical_id(item)


def final_outcome(phases: dict[str, str]) -> str:
    """One outcome from an item's setup/call/teardown outcomes: ``failed`` (the test),
    ``error`` (setup or teardown), else the call outcome (``passed``, ``skipped``,
    ``xfailed``, ``xpassed``)."""
    if phases.get("call") == "failed":
        return "failed"
    if "failed" in phases.values():
        return "error"
    if "call" in phases:
        return phases["call"]
    if phases.get("setup") == "passed":
        return "incomplete"  # set up but never called: the run stopped early
    return phases.get("setup", "incomplete")


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("shard", "run one slice of the collected tests")
    group.addoption("--shard", default=None, metavar="K/N", help="run shard K of N (1 <= K <= N)")
    group.addoption(
        "--shard-suite",
        default=None,
        metavar="NAME",
        help="with --shard-report, the suite the report belongs to (test, test-locked)",
    )
    group.addoption(
        "--shard-report",
        default=None,
        metavar="PATH",
        help="with --shard, write the shard report JSON to PATH",
    )


def pytest_configure(config: pytest.Config) -> None:
    spec = config.getoption("shard")
    report = config.getoption("shard_report")
    suite = config.getoption("shard_suite")
    if spec is None:
        if report is not None or suite is not None:
            raise pytest.UsageError("--shard-report and --shard-suite need --shard")
        return
    if report is not None and not suite:
        raise pytest.UsageError("--shard-report needs --shard-suite")
    try:
        k, n = partition().parse_shard(spec)
    except ValueError as exc:
        raise pytest.UsageError(f"--shard: {exc}") from exc
    config.pluginmanager.register(_Shard(config, k, n, report, suite), "unifi-shard")


class _Shard:
    def __init__(
        self, config: pytest.Config, k: int, n: int, report: str | None, suite: str | None
    ) -> None:
        self.config = config
        self.suite = suite
        self.k = k
        self.n = n
        self.report = report
        self.is_worker = hasattr(config, "workerinput")
        self.phases: dict[str, dict[str, str]] = {}
        self.collected: list[dict[str, Any]] = []  # workeroutput of each worker, or own

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, config, items) -> None:
        part = partition()
        ids = [canonical_id(item) for item in items]
        placement = part.assign({unit_of(item) for item in items}, heavy_weights(), self.n)
        keep, drop, selected = [], [], []
        for item, nodeid in zip(items, ids, strict=True):
            if placement[unit_of(item)] == self.k:
                keep.append(item)
                selected.append(nodeid)
            else:
                drop.append(item)
        if drop:
            config.hook.pytest_deselected(items=drop)
        items[:] = keep
        mine = {
            "full_sha256": part.ids_digest(ids),
            "full_count": len(ids),
            "selected": selected,
            "groups": sorted({unit_of(item) for item in keep if _group_names(item)}),
        }
        if self.is_worker:
            config.workeroutput["unifi_shard"] = mine  # type: ignore[attr-defined]
        else:
            self.collected = [mine]

    def pytest_runtest_logreport(self, report) -> None:
        if self.is_worker or report.when is None:
            return
        outcome = report.outcome
        if report.when == "call" and hasattr(report, "wasxfail"):
            outcome = {"skipped": "xfailed", "passed": "xpassed"}.get(outcome, outcome)
        self.phases.setdefault(report.nodeid, {})[report.when] = outcome

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node, error) -> None:
        output = getattr(node, "workeroutput", None) or {}
        if "unifi_shard" in output:
            self.collected.append(output["unifi_shard"])

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session) -> None:
        if self.is_worker or self.report is None:
            return
        # Every worker collects the same list (xdist enforces it); disagreement or a
        # worker that never reported leaves the shard's report short, which fails closed.
        first = self.collected[0] if self.collected else {}
        agree = all(c == first for c in self.collected)
        selected = list(first.get("selected", [])) if agree else []
        known = set(selected)
        outcomes: dict[str, str] = {}
        for nodeid, phases in self.phases.items():
            base = nodeid.rsplit("@", 1)[0] if nodeid not in known and "@" in nodeid else nodeid
            outcomes[base if base in known else nodeid] = final_outcome(phases)
        env = env_identity().record(ROOT / "requirements.lock", ROOT)
        data = {
            "format": 1,
            "suite": self.suite,
            "commit": os.environ.get("GITHUB_SHA") or _head(),
            "run": os.environ.get("GITHUB_RUN_ID"),
            "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "k": self.k,
            "n": self.n,
            "full_sha256": first.get("full_sha256") if agree else None,
            "full_count": first.get("full_count") if agree else None,
            "groups": list(first.get("groups", [])) if agree else [],
            "selected": selected,
            "outcomes": outcomes,
            "identity": env["identity"],
            "lock_errors": env["lock_errors"],
            "install_seconds": _install_seconds(),
        }
        path = Path(self.report)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=0))
        tmp.replace(path)


def _install_seconds() -> float | None:
    """Time the job's install step took, as the workflow records it (informational)."""
    try:
        return float(os.environ["SHARD_INSTALL_SECONDS"])
    except (KeyError, ValueError):
        return None


def _head() -> str | None:
    try:
        result = subprocess.run(  # noqa: S603 - fixed command
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return result.stdout.strip() or None
