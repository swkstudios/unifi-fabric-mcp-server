"""Release the captured output of passing tests once every live consumer has seen it.

The terminal reporter keeps every report it logs until the session summary, including
the passing setup and teardown reports (category ``""``). Each report also carries the
captured stdout, stderr and log sections of its own phase and of every earlier phase.
Under xdist the controller receives the reports from all workers, so it held the
captured output of the whole suite: the controller of a full run grew past 900 MB and
was killed by the runner cgroup's OOM killer.

Only two summary paths print the sections of a passing report: the ``-rP`` (or
``-rA``) passes summary, and the failure/error summary, which prints the teardown
sections of a failed test. This plugin therefore trims nothing while the passes summary
is requested, and otherwise empties the sections of a test's reports only when its
setup, call and teardown all passed (no xfail/xpass). It runs ``trylast`` on the
teardown report, after every other ``pytest_runtest_logreport`` consumer (terminal
output, junitxml, xdist forwarding) has handled the full report. The reports, their
outcomes, durations and counts stay in place for the summary, ``--durations`` and
``--lf``; a failed, errored, skipped or xfail test keeps everything.
"""

from __future__ import annotations

import pytest


class ReportRetention:
    def __init__(self, config: pytest.Config) -> None:
        self._config = config
        self._phases: dict[tuple[str, int], list[pytest.TestReport]] = {}
        # The item that produced each teardown report, until that report is logged.
        self._items: dict[str, pytest.Item] = {}

    def _passes_summary_requested(self) -> bool:
        reporter = self._config.pluginmanager.get_plugin("terminalreporter")
        # Without a terminal reporter, keep everything for whichever plugin replaced it.
        return reporter is None or "P" in reporter.reportchars

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_makereport(self, item: pytest.Item, call: pytest.CallInfo[None]):
        report = yield
        if report.when == "teardown":
            self._items[report.nodeid] = item
        return report

    @pytest.hookimpl(trylast=True)
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        # xdist sets ``report.node`` on the controller. Key by worker so a node id that
        # several workers run (``--dist each``) never mixes their phases.
        key = (report.nodeid, id(getattr(report, "node", None)))
        phases = self._phases.setdefault(key, [])
        phases.append(report)
        if report.when != "teardown":
            return
        del self._phases[key]
        item = self._items.pop(report.nodeid, None)
        if self._passes_summary_requested():
            return
        if all(rep.passed and not hasattr(rep, "wasxfail") for rep in phases):
            for rep in phases:
                rep.sections = []
            # Each report holds a copy: the item keeps the captured text of every phase
            # (``Item._report_sections``) for as long as the session holds the item, that
            # is the whole run, in a worker as much as in the controller. Reports are
            # built from it only while the phases run, so a passed test no longer needs it.
            if item is not None:
                item._report_sections.clear()


def pytest_configure(config: pytest.Config) -> None:
    config.pluginmanager.register(ReportRetention(config), "unifi-report-retention")
