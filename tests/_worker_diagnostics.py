"""Preserve process exit evidence and peak memory when an xdist worker disappears.

Each worker reports its peak resident set size (``ru_maxrss``) with every test report it
sends, and once more when it finishes. The controller prints each worker's peak when the
worker goes down and lists all of them, with its own, in the terminal summary. A worker
the kernel kills (an out-of-memory kill sends no final report) is listed with the peak it
had reached after its last finished test phase, and that test's node id.
"""

from __future__ import annotations

import signal
import sys
from collections.abc import Generator
from typing import Any

import pytest

try:
    import resource
except ImportError:  # not POSIX: no getrusage, so no peaks are reported
    resource = None  # type: ignore[assignment]

#: Crashed workers whose process had not been reaped when xdist reported the node down.
_pending = pytest.StashKey[list[tuple[str, Any, Any]]]()

#: The worker's peak RSS in bytes, set on each report a worker sends to the controller.
_REPORT_PEAK = "worker_peak_rss_bytes"
#: The worker's peak RSS in bytes at the end of its session, in ``workeroutput``.
_FINAL_PEAK = "peak_rss_bytes"
_TOP = "peak_rss_top_tests"
_FIXTURE = "peak_rss_catalog_fixture"
_tracker = pytest.StashKey["_RssSteps"]()


def _detail(gateway_id: str, pid: Any, returncode: int | None) -> str:
    detail = f"worker process exit: {gateway_id} pid={pid} returncode={returncode}"
    if returncode is not None and returncode < 0:
        try:
            signame = signal.Signals(-returncode).name
        except ValueError:
            signame = "unknown"
        detail += f" signal={signame} ({-returncode})"
    elif returncode is None:
        detail += " (not observed; process may still be alive)"
    return detail


def _write(config: pytest.Config, line: str) -> None:
    terminal = config.pluginmanager.getplugin("terminalreporter")
    if terminal is not None:
        terminal.write_line(line)


def _peak_rss() -> int | None:
    """This process's peak resident set size in bytes, or None without getrusage."""
    if resource is None:
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kibibytes, macOS bytes.
    return peak if sys.platform == "darwin" else peak * 1024


def _mib(size: int) -> str:
    return f"{size / 2**20:.1f} MiB"


class _RssSteps:
    """Keep the largest high-water increases in bounded space."""

    def __init__(self, initial: int | None) -> None:
        self.previous = initial
        self.steps: list[tuple[int, int, str]] = []
        self.fixture: tuple[int, int] | None = None

    def record(self, nodeid: str, after: int | None) -> None:
        if after is not None and self.previous is not None:
            self.steps.append((self.previous, after, nodeid))
            self.steps.sort(key=lambda step: (-(step[1] - step[0]), step[2]))
            del self.steps[15:]
        if after is not None:
            self.previous = after

    def lines(self, worker: str) -> list[str]:
        return [
            f"worker RSS step: {worker} {nodeid} {_mib(before)} -> {_mib(after)} "
            f"(+{_mib(after - before)})"
            for before, after, nodeid in self.steps
        ]


def _fixture_line(worker: str, step: tuple[int, int]) -> str:
    before, after = step
    return (
        f"worker RSS fixture: {worker} _warm_tool_catalog "
        f"{_mib(before)} -> {_mib(after)} (+{_mib(after - before)})"
    )


class _WorkerPeaks:
    """The controller's record of each worker's peak RSS, by gateway id."""

    def __init__(self) -> None:
        # gateway id -> (peak bytes, node id of the report that carried it, final)
        self.peaks: dict[str, tuple[int, str | None, bool]] = {}
        self.steps: dict[str, list[str]] = {}
        self.fixtures: dict[str, tuple[int, int]] = {}

    @pytest.hookimpl(trylast=True)
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        peak = getattr(report, _REPORT_PEAK, None)
        gateway = getattr(getattr(report, "node", None), "gateway", None)
        if peak is None or gateway is None:
            return
        known = self.peaks.get(gateway.id)
        self.peaks[gateway.id] = (max(peak, known[0] if known else 0), report.nodeid, False)

    def node_down(self, node: Any) -> str:
        gateway_id = node.gateway.id
        output = getattr(node, "workeroutput", None) or {}
        final = output.get(_FINAL_PEAK)
        self.steps[gateway_id] = output.get(_TOP, [])
        if output.get(_FIXTURE) is not None:
            self.fixtures[gateway_id] = output[_FIXTURE]
        if final is not None:
            known = self.peaks.get(gateway_id)
            self.peaks[gateway_id] = (max(final, known[0] if known else 0), None, True)
        return self.line(gateway_id)

    def line(self, gateway_id: str) -> str:
        known = self.peaks.get(gateway_id)
        if known is None:
            return f"worker peak RSS: {gateway_id} unknown (no report reached the controller)"
        peak, nodeid, final = known
        if final:
            return f"worker peak RSS: {gateway_id} ru_maxrss={_mib(peak)}"
        return (
            f"worker peak RSS: {gateway_id} ru_maxrss>={_mib(peak)} (the worker sent no "
            f"final report; peak as of its last report, {nodeid})"
        )


def pytest_configure(config: pytest.Config) -> None:
    config.stash[_tracker] = _RssSteps(_peak_rss())
    if not hasattr(config, "workerinput"):
        config.pluginmanager.register(_WorkerPeaks(), "unifi-worker-peaks")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    worker = hasattr(item.config, "workerinput")
    if worker or report.when == "teardown":
        peak = _peak_rss()
        if worker and peak is not None:
            setattr(report, _REPORT_PEAK, peak)
        if report.when == "teardown":
            item.config.stash[_tracker].record(item.nodeid, peak)
    return report


@pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(
    fixturedef: Any, request: pytest.FixtureRequest
) -> Generator[None, Any, Any]:
    if fixturedef.scope != "session" or fixturedef.argname != "_warm_tool_catalog":
        return (yield)
    before = _peak_rss()
    try:
        return (yield)
    finally:
        after = _peak_rss()
        if before is not None and after is not None:
            tracker = request.config.stash[_tracker]
            tracker.fixture = (before, after)
            tracker.previous = after


def pytest_sessionfinish(session: pytest.Session) -> None:
    # xdist sends ``workeroutput`` to the controller after every sessionfinish hook.
    workeroutput = getattr(session.config, "workeroutput", None)
    peak = _peak_rss()
    if workeroutput is not None and peak is not None:
        workeroutput[_FINAL_PEAK] = peak
        tracker = session.config.stash[_tracker]
        workeroutput[_TOP] = tracker.lines(getattr(session.config, "workerinput", {})["workerid"])
        workeroutput[_FIXTURE] = tracker.fixture


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    peaks = node.config.pluginmanager.get_plugin("unifi-worker-peaks")
    if peaks is not None:
        _write(node.config, peaks.node_down(node))
    if error is None:
        return
    # xdist's generic channel-EOF error omits the local child's exit status.
    # Only inspect the process: a live child or remote gateway stays unknown.
    process = getattr(getattr(node.gateway, "_io", None), "popen", None)
    if process is None:
        _write(node.config, _detail(node.gateway.id, "unknown", None))
        return
    returncode = process.poll()
    if returncode is None:
        # The channel reaches EOF while the exiting child closes its descriptors, before
        # the kernel lets it be reaped; a loaded host reports the node down inside that
        # window. xdist's session teardown waits for every worker process, so report
        # this one from the terminal summary, after that wait.
        node.config.stash.setdefault(_pending, []).append((node.gateway.id, process.pid, process))
        return
    _write(node.config, _detail(node.gateway.id, process.pid, returncode))


def pytest_terminal_summary(terminalreporter, config):
    for gateway_id, pid, process in config.stash.get(_pending, []):
        terminalreporter.write_line(_detail(gateway_id, pid, process.poll()))
    peaks = config.pluginmanager.get_plugin("unifi-worker-peaks")
    if peaks is not None:
        for gateway_id in sorted(peaks.peaks, key=lambda gw: (len(gw), gw)):
            terminalreporter.write_line(peaks.line(gateway_id))
            for line in peaks.steps.get(gateway_id, []):
                terminalreporter.write_line(line)
            if gateway_id in peaks.fixtures:
                terminalreporter.write_line(_fixture_line(gateway_id, peaks.fixtures[gateway_id]))
        if not peaks.peaks:
            tracker = config.stash[_tracker]
            for line in tracker.lines("main"):
                terminalreporter.write_line(line)
            if tracker.fixture is not None:
                terminalreporter.write_line(_fixture_line("main", tracker.fixture))
    own = _peak_rss()
    if own is not None:
        terminalreporter.write_line(f"pytest process peak RSS: ru_maxrss={_mib(own)}")
