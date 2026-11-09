"""Every docs/TOOL-USAGE.md example runs against the local mock; the standalone exercise works.

Hermetic: the mock binds 127.0.0.1 on an ephemeral port, the key is the synthetic `api-key-1`,
the server runs in dry-run and no real host or account is contacted.
"""

import asyncio
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "run_tool_usage_examples.py"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("run_tool_usage_examples", RUNNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_all(runner, examples):
    server, base_url = runner.start_mock()
    try:
        return asyncio.run(runner.run(examples, base_url))
    finally:
        server.shutdown()
        server.server_close()


def test_tool_usage_examples_all_pass_against_mock(runner):
    examples = runner.parse_examples(runner.DOC.read_text())
    assert len(examples) == 38, "docs/TOOL-USAGE.md now holds a different number of examples"
    records = _run_all(runner, examples)
    assert [r["example_id"] for r in records] == list(range(1, len(examples) + 1))
    assert {r["tool"] for r in records} == {e["tool"] for e in examples}
    not_pass = [(r["example_id"], r["tool"], r["result"], r.get("error")) for r in records]
    assert all(r["result"] == "pass" for r in records), not_pass
    assert sum(1 for r in records if r["result"] == "mock-gap") == 0
    assert sum(r["upstream_mutations"] for r in records) == 0
    assert all(r["mode"] == "dry-run" for r in records)


def test_runner_report_and_exit_status(tmp_path):
    report = tmp_path / "examples.json"
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(RUNNER), "--report", str(report)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    records = json.loads(report.read_text())
    assert len(records) == 38
    assert set(records[0]) >= {
        "example_id",
        "doc_line",
        "tool",
        "mode",
        "mock_route",
        "mock_method",
        "result",
        "upstream_mutations",
        "fix_slice",
    }


def test_runner_flags_a_route_the_mock_lacks(runner):
    example = {
        "example_id": 1,
        "doc_line": 1,
        "tool": "fabric_connector_get",
        "args": {"host": "my-console", "path": "network/integration/v1/no-such-route"},
    }
    (record,) = _run_all(runner, [example])
    assert record["result"] == "mock-gap"
    assert record["upstream_mutations"] == 0


def test_mock_serves_the_change_027_read_routes(runner):
    mock = runner.mock_api
    calls = [
        ("get_host", {"host": "main-office-gw"}),
        ("get_sdwan_config", {"config_id": mock.SDWAN_CONFIG_ID}),
        ("get_sdwan_config_status", {"config_id": mock.SDWAN_CONFIG_ID}),
        ("get_carrier_subscriber", {"subscriber_id": mock.CARRIER_SUBSCRIBER_ID}),
        ("get_carrier_service_plan", {"plan_id": mock.CARRIER_PLAN_ID}),
        (
            "get_mobility_device",
            {"workspace_id": mock.MOBILITY_WORKSPACE_ID, "device_id": mock.MOBILITY_DEVICE_ID},
        ),
        ("get_innerspace_project", {"host": "main-office-gw"}),
    ]
    examples = [
        {"example_id": i, "doc_line": 0, "tool": tool, "args": args}
        for i, (tool, args) in enumerate(calls, start=1)
    ]
    records = _run_all(runner, examples)
    assert [(r["tool"], r["result"], r.get("error")) for r in records] == [
        (tool, "pass", None) for tool, _ in calls
    ]
    assert all(r["mock_method"] == "GET" for r in records)


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_standalone_mock_exercise_runs():
    port = _free_port()
    mock = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "tests" / "support" / "tool_usage_mock" / "mock_api.py"),
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        url = f"http://127.0.0.1:{port}"
        while True:
            try:
                urllib.request.urlopen(f"{url}/_demo/requests").close()  # noqa: S310
                break
            except OSError:
                assert mock.poll() is None, "the mock exited before it served a request"
                time.sleep(0.2)
        env = {**os.environ, "UNIFI_API_BASE_URL": url}
        done = subprocess.run(  # noqa: S603
            [
                sys.executable,
                str(ROOT / "tests" / "support" / "tool_usage_mock" / "standalone_exercise.py"),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        mock.terminate()
        mock.wait()
    assert done.returncode == 0, done.stdout + done.stderr
    assert "list_hosts: 3 results" in done.stdout
    assert "list_sites: 3 results" in done.stdout
    assert "list_devices:" in done.stdout
    assert "writes: 0" in done.stdout


def test_mock_site_client_counts_match_served_clients():
    spec = importlib.util.spec_from_file_location(
        "demo_mock_api", ROOT / "tests/support/tool_usage_mock/mock_api.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    model = module.build(json.loads(module.FIXTURES.read_text()))
    for site in model["sites"]:
        clients = model["consoles"][site["hostId"]]["clients"]
        counts = site["statistics"]["counts"]
        assert counts["wifiClient"] == sum(not c["is_wired"] for c in clients)
        assert counts["wiredClient"] == sum(c["is_wired"] for c in clients)
        assert counts["guestClient"] == sum(c["is_guest"] for c in clients)
