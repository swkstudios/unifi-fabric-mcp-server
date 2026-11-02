"""Upstream error bodies reach the caller, never the logs.

docs/CONFIGURATION.md (``UNIFI_LOG_LEVEL``): logs go to stderr only and request/response
bodies are never logged. A failed upstream call is reported in the tool result with its
complete body; a log line about it names the method, path, status and a bounded reason
code only.

The generic property drives every registered tool against an upstream whose every
request (or every request but the host and site enumeration) answers HTTP 500 with a
sentinel body, captures every log record at DEBUG, and asserts the sentinel is in no
record. The site-level tests pin the four fan-out sites that logged the exception text.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_classes import class_axis
from unifi_fabric.client import UniFiConnectionError

BODY_SENTINEL = "upstream-error-body-sentinel-7f3a"
ERROR_BODY = json.dumps({"code": "server_error", "message": BODY_SENTINEL})


def _http_500(path: str) -> UniFiConnectionError:
    """The client's error for an HTTP 500 answer: the complete body, and its status."""
    exc = UniFiConnectionError(f"HTTP 500 from GET {path}: {ERROR_BODY}")
    exc.status = 500
    return exc


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def captured_logs():
    """Every record at DEBUG, formatted; ``_quiet_logs`` of the shared module is not used."""
    handler = _Capture()
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _error_upstream(resolution: bool) -> uh.FakeUpstream:
    return uh.FakeUpstream(
        mode="error", error_status=500, error_body=ERROR_BODY, error_resolution=resolution
    )


async def _drive(monkeypatch, name: str, up: uh.FakeUpstream) -> str:
    """The tool's result or error text, as the caller receives it."""
    try:
        res = await cti._call(monkeypatch, name, up)
    except ToolError as exc:
        return str(exc)
    return json.dumps(uh.result_payload(res), default=str)


@class_axis(
    "name", lambda: sorted(cti._lz_TOOLS()), failing=lambda: ["every-request", "tool-requests"]
)
async def test_upstream_error_body_never_logged(monkeypatch, captured_logs, name, failing):
    await _drive(monkeypatch, name, _error_upstream(failing == "every-request"))
    leaked = [line for line in captured_logs.lines if BODY_SENTINEL in line]
    assert leaked == [], f"{name} [{failing}]: upstream error body logged: {leaked[:2]}"


# --------------------------------------------------------------- the fan-out sites
async def test_fleet_console_names_failure_logs_no_body(monkeypatch, captured_logs):
    """aggregation: the console-name lookup (GET /v1/hosts) failing is logged as a
    status and reason code; the body is never in the log line."""
    from unifi_fabric.tools import aggregation

    async def failing_hosts(*args: Any, **kwargs: Any) -> Any:
        raise _http_500("/v1/hosts")

    up = uh.FakeUpstream(replay_recordings=False)
    uh.install(monkeypatch, up)
    from unifi_fabric import server

    monkeypatch.setattr(server._registry, "get_hosts", failing_hosts)
    await aggregation._get_all_host_site_pairs(server._registry)
    joined = "\n".join(captured_logs.lines)
    assert "Could not list hosts for console names" in joined
    assert "HTTP 500" in joined
    assert BODY_SENTINEL not in joined


async def test_fleet_site_list_failure_logs_no_body_and_reports_it(monkeypatch, captured_logs):
    """aggregation: a console's site list failing is logged without the body; the
    complete error stays in the tool result (``_skipped[].reason``)."""
    from unifi_fabric import server
    from unifi_fabric.tools import aggregation

    async def failing_sites(*args: Any, **kwargs: Any) -> Any:
        raise _http_500("/proxy/network/sites")

    up = uh.FakeUpstream(replay_recordings=False)
    uh.install(monkeypatch, up)
    monkeypatch.setattr(server._registry, "get_sites", failing_sites)
    skipped: list[dict[str, str]] = []
    await aggregation._get_all_host_site_pairs(server._registry, skipped=skipped)
    joined = "\n".join(captured_logs.lines)
    assert "Failed to fetch proxy sites for host" in joined
    assert "HTTP 500" in joined
    assert BODY_SENTINEL not in joined
    assert skipped and all(BODY_SENTINEL in s["reason"] for s in skipped)


async def _search(monkeypatch, up: uh.FakeUpstream) -> str:
    """search_across_sites over ``up``: its result or error text, as the caller sees it."""
    return await _drive_args(monkeypatch, "search_across_sites", up, {"query": "probe"})


async def _drive_args(monkeypatch, name: str, up: uh.FakeUpstream, args: dict) -> str:
    try:
        res = await cti._call(monkeypatch, name, up, args=args)
    except ToolError as exc:
        return str(exc)
    return json.dumps(uh.result_payload(res), default=str)


async def test_search_scope_failure_logs_no_body_and_reports_it(monkeypatch, captured_logs):
    """site_manager.search_across_sites: a site's devices/clients read failing is logged
    as scope, site, status; the complete error (body included) reaches the caller."""
    up = uh.FakeUpstream(
        mode="error", error_status=500, error_body=ERROR_BODY, error_resolution=False
    )
    seen = await _search(monkeypatch, up)
    joined = "\n".join(captured_logs.lines)
    assert "devices fetch failed" in joined
    assert "HTTP 500" in joined
    assert BODY_SENTINEL not in joined
    assert BODY_SENTINEL in seen


async def test_search_site_skip_logs_no_body_and_reports_it(monkeypatch, captured_logs):
    """site_manager.search_across_sites: a site skipped because its console site could
    not be resolved is logged with a reason code; the complete error reaches the caller."""
    from unifi_fabric.tools import site_manager

    async def failing(*args: Any, **kwargs: Any) -> Any:
        raise _http_500("/proxy/network/sites")

    monkeypatch.setattr(site_manager, "_proxy_site_for_ea", failing)
    seen = await _search(monkeypatch, uh.FakeUpstream(replay_recordings=False))
    joined = "\n".join(captured_logs.lines)
    assert "skipping site" in joined
    assert "HTTP 500" in joined
    assert BODY_SENTINEL not in joined
    assert BODY_SENTINEL in seen


def _wrapped(cause: Exception) -> Exception:
    try:
        raise UniFiConnectionError(f"{cause}; outcome unknown") from cause
    except UniFiConnectionError as exc:
        return exc


@pytest.mark.parametrize(
    ("make", "expected"),
    [
        (lambda: _http_500("/v1/hosts"), "HTTP 500"),
        (lambda: _wrapped(_http_500("/v1/hosts")), "HTTP 500"),
        (lambda: UniFiConnectionError(f"Unexpected shape: {ERROR_BODY}"), "UniFiConnectionError"),
        (lambda: ValueError(ERROR_BODY), "ValueError"),
    ],
)
def test_log_reason_is_bounded(make, expected):
    from unifi_fabric.client import log_reason

    assert log_reason(make()) == expected
