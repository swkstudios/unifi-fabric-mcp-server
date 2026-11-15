"""``--shard K/N``: run one deterministic slice of the collected test items.

Inert unless ``--shard`` is given. The selection is a pure function of the collected IDs,
the committed heavy list (``tests/shard_heavy_units.json``) and a fixed salt
(``scripts/shard_partition.py``). The unit of assignment is the ``xdist_group`` name when
an item has one (a group never splits), else the item's node ID.

The selection is applied while collecting. As each collector's report is handled, the ``-m``
and ``-k`` deselection is applied to them, every surviving ID is recorded for the proof, and
the items of other shards are dropped (``pytest_deselected``) before the next module is
collected. A worker therefore holds one module's items of other shards at a time, not the
whole suite's (about 7 KiB each). The heavy units are the exception: their placement depends
on which heavy units are present, so their items are kept until the hook that runs last, after
the ``-m`` and ``-k`` deselection, places them; its input is then the item list an unsharded
run would execute, less the light units of other shards. ``--shard-prune-late`` does all of
the selection in that hook instead. The late path is also used whenever the early cut could
select differently: ``--deselect``, ``--lf``, ``--ff``, ``--sw`` (and its ``-skip`` / ``-reset``
forms), a node id on the command line, any ``-k``, and any ``-m`` naming a marker the repo does
not apply as a decorator (a plugin such as hypothesis adds markers in its own
``pytest_collection_modifyitems``, after the early cut).

With ``--shard-report PATH`` the run writes a JSON report: commit,
run, K, N, the sha256 of the sorted full pre-selection ID list, the selected IDs and the
final outcome per executed ID (read where results arrive: the xdist controller, or the
single process). ``scripts/shard_partition.py verify`` checks the reports of all shards
against an independent plain collection.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
HEAVY_UNITS = Path(__file__).with_name("shard_heavy_units.json")
_PARTITION_PATH = ROOT / "scripts" / "shard_partition.py"
_IDENTITY_PATH = ROOT / "scripts" / "env_identity.py"


class _Deselected:
    """Stands for a deselected item in the terminal reporter's count."""


_DESELECTED = _Deselected()


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


def heavy_weights(path: Path | None = None) -> dict[str, float]:
    """Unit -> measured seconds for the committed heavy units."""
    data = json.loads((path or HEAVY_UNITS).read_text())
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
        help="with --shard-report, the suite the report belongs to (test, scrub-oracle)",
    )
    group.addoption(
        "--shard-prune-late",
        action="store_true",
        default=False,
        help="with --shard, drop the other shards' items after collection, not while collecting",
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


def _mark_deselection():
    """pytest's own ``-k`` / ``-m`` deselection, which the late path gets from its plugin."""
    from _pytest import mark

    return mark


#: Markers the repo applies with a decorator (``pyproject.toml`` ``markers``), so they are on an
#: item when its collector reports it. Any other name in ``-m`` may be added later by a plugin.
STATIC_MARKERS = frozenset({"mutating", "slow", "integration", "tls"})
_MARK_WORDS = frozenset({"and", "or", "not"})


def _static_markexpr(expression: str) -> bool:
    """Whether a ``-m`` expression names only markers that are decorators in this repo."""
    names = [t for t in re.findall(r"[^\s()]+", expression) if t not in _MARK_WORDS]
    return all(name in STATIC_MARKERS for name in names)


def _prunes_while_collecting(config: pytest.Config) -> bool:
    """Whether the other shards' items can be dropped as each collector reports them.

    That is only the same selection when nothing else shapes the item list or decides what
    ``-m`` / ``-k`` see: no ``--deselect``, no last-failed / failed-first / stepwise ordering
    (read after every plugin has configured: stepwise turns itself on for ``--sw-skip`` and
    ``--sw-reset`` in its own ``pytest_configure``), no node id on the command line (pytest
    narrows to it after the module is reported), no ``-k``, and a ``-m`` that names only
    decorator markers (a plugin adds its own markers later, in ``pytest_collection_modifyitems``).
    Otherwise the shard is cut after collection.
    """
    if config.getoption("shard_prune_late"):
        return False
    option = config.option
    if getattr(option, "deselect", None) or any(
        getattr(option, name, False)
        for name in ("lf", "failedfirst", "stepwise", "stepwise_skip", "stepwise_reset")
    ):
        return False
    if any("::" in str(arg) for arg in config.args):
        return False
    if str(getattr(option, "keyword", "") or "").strip():
        return False
    if not _static_markexpr(str(getattr(option, "markexpr", "") or "")):
        return False
    try:
        mark = _mark_deselection()
        return callable(mark.deselect_by_keyword) and callable(mark.deselect_by_mark)
    except (ImportError, AttributeError):
        return False


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
        self._early = False  # decided at session start, once every plugin has configured
        self._heavy: frozenset[str] = frozenset()
        self._ids: list[str] = []  # every ID an unsharded run would execute, when pruning early
        self._released = 0  # deselected entries of the terminal reporter already replaced

    def pytest_sessionstart(self, session) -> None:
        self._early = _prunes_while_collecting(self.config)
        self._heavy = frozenset(heavy_weights()) if self._early else frozenset()

    def _release_deselected(self, config: pytest.Config) -> None:
        """Replace the terminal reporter's deselected items by placeholders.

        The reporter keeps every deselected item for the summary count, which would keep the
        whole suite's items alive in each worker. The summary reads only how many there were;
        plugins that walk every stat list (hypothesis reads ``report.__dict__``) need an
        object with a ``__dict__``.
        """
        reporter = config.pluginmanager.get_plugin("terminalreporter")
        held = reporter.stats.get("deselected") if reporter is not None else None
        if held:
            held[self._released :] = [_DESELECTED] * (len(held) - self._released)
            self._released = len(held)

    @pytest.hookimpl(wrapper=True)
    def pytest_make_collect_report(self, collector):
        # Before the session walks the report's items (it reports the collector itself only
        # after its children), so the next collector starts with the other shards' items gone.
        report = yield
        if self._early and report.result:
            self._prune(collector.config, report.result)
        return report

    def _prune(self, config: pytest.Config, result: list[Any]) -> None:
        """Apply ``-k``/``-m`` to a collector's items, record the survivors, drop other shards'."""
        items = [node for node in result if isinstance(node, pytest.Item)]
        if not items:
            return
        survivors = list(items)
        mark = _mark_deselection()
        mark.deselect_by_keyword(survivors, config)
        mark.deselect_by_mark(survivors, config)
        part = partition()
        keep: set[int] = set()
        drop = []
        for item in survivors:
            self._ids.append(canonical_id(item))
            unit = unit_of(item)
            if unit in self._heavy or part.hash_shard(unit, self.n) == self.k:
                keep.add(id(item))
            else:
                drop.append(item)
        # What the markers and expressions removed went through pytest_deselected already.
        if drop:
            config.hook.pytest_deselected(items=drop)
        self._release_deselected(config)
        drop.clear()
        removed = len(items) - len(keep)
        result[:] = [
            node for node in result if not isinstance(node, pytest.Item) or id(node) in keep
        ]
        # The terminal reporter counts a collector's items when it is reported, after this cut,
        # and prints "selected/collected (N deselected)": the collected count is every item.
        reporter = config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None and isinstance(getattr(reporter, "_numcollected", None), int):
            reporter._numcollected += removed

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
            self._release_deselected(config)
        drop.clear()
        items[:] = keep
        if self._early:
            # The items left are this shard's and the heavy units'; the proof is against
            # every ID an unsharded run would execute, recorded while collecting.
            ids = self._ids
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
