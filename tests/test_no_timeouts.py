"""Mechanical regression guard for elapsed-time caps."""

import json
import subprocess
from pathlib import Path

import pytest

from scripts.check_no_timeouts import (
    ALLOWLIST,
    check_allowlist,
    repository_findings,
    scan_text,
    tracked_paths,
)

ROOT = Path(__file__).resolve().parents[1]


def test_allowlist_contains_only_the_approved_entries():
    entries = json.loads((ROOT / ALLOWLIST).read_text())
    assert {entry["path"] for entry in entries} == {
        "Dockerfile",
        "docs/TLS.md",
        "src/unifi_fabric/code_mode.py",
    }
    assert [e["class"] for e in entries].count("sandbox-interpreter-cpu") == 1
    assert all(
        set(entry) == {"path", "pattern", "class", "citation", "verdict", "added"}
        for entry in entries
    )
    assert check_allowlist(ROOT) == []


def test_allowlist_rejects_unrecognized_private_verdict(tmp_path):
    entries = json.loads((ROOT / ALLOWLIST).read_text())
    entries[0]["verdict"] = "unrecognised-verdict-for-this-class"
    target = tmp_path / ALLOWLIST
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(entries))
    assert check_allowlist(tmp_path)


def test_allowlist_rejects_stale_or_malformed_exceptions(tmp_path):
    (tmp_path / "docs").mkdir()
    entries = json.loads((ROOT / ALLOWLIST).read_text())
    (tmp_path / ALLOWLIST).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / ALLOWLIST).write_text(json.dumps(entries))
    (tmp_path / "Dockerfile").write_text(
        "HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 CMD true\n"
    )
    (tmp_path / "docs/TLS.md").write_text(
        "```dockerfile\n"
        "HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 CMD true\n"
        "```\n"
    )
    (tmp_path / "src/unifi_fabric").mkdir(parents=True)
    (tmp_path / "src/unifi_fabric/code_mode.py").write_text(
        'LIMITS = {\n    "max_feed_duration_secs": CPU_SECONDS_LIMIT,\n}\n'
    )
    subprocess.run(  # noqa: S607 - fixed executable; no user input is passed
        ["git", "init", "--quiet"],  # noqa: S607 - fixed executable, no user input
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(  # noqa: S607 - fixed executable; no user input is passed
        ["git", "add", "--all"],  # noqa: S607 - fixed executable, no user input
        cwd=tmp_path,
        check=True,
    )
    assert repository_findings(tmp_path) == []

    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n")
    stale = repository_findings(tmp_path)
    assert any("stale exception pattern for Dockerfile" in finding for finding in stale)

    entries[0].pop("added")
    (tmp_path / ALLOWLIST).write_text(json.dumps(entries))
    malformed = repository_findings(tmp_path)
    assert any("exact six-field schema" in finding for finding in malformed)


def test_full_ci_runs_the_mechanical_policy_gate():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "- name: Enforce no-timeout policy" in workflow
    step = workflow.split("- name: Enforce no-timeout policy", 1)[1].split("- name:", 1)[0]
    # The private tree adds one scanner flag that the public transform removes
    # (pinned in the private-only workflow-forms test); both run the full scanner.
    assert "run: python scripts/check_no_timeouts.py" in step


def test_python_cap_constructs_are_reported():
    source = """
client = httpx.Client(timeout=5)
await asyncio.wait_for(operation(), 10)
worker.join(timeout=3)
worker.join(3)
deadline = time.monotonic() + allowance
"""
    findings = scan_text(Path("src/example.py"), source)
    assert len(findings) == 5
    assert any("timeout argument" in finding for finding in findings)
    assert any("wait_for call" in finding for finding in findings)
    assert any("timed join call" in finding for finding in findings)
    assert any("monotonic clock plus budget" in finding for finding in findings)


def test_python_parse_errors_fail_closed():
    findings = scan_text(Path("src/example.py"), "def broken(:\n")
    assert len(findings) == 1 and "Python parse error" in findings[0]


def test_scanner_tracks_itself_dotgithub_and_nested_markdown():
    paths = set(tracked_paths(ROOT))
    assert Path("scripts/check_no_timeouts.py") in paths
    assert Path("tests/test_no_timeouts.py") in paths
    assert Path(".github/workflows/ci.yml") in paths
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "docs"],  # noqa: S607 - fixed executable
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode()
    nested_markdown = {
        Path(rel) for rel in listed.split("\0") if rel.endswith(".md") and rel.count("/") > 1
    }
    assert nested_markdown <= paths
    assert scan_text(Path(".github/lychee.toml"), "timeout = 12\n")


def test_qualified_timeout_aliases_and_embedded_helper_are_reported():
    findings = scan_text(Path("src/example.py"), "client = httpx2.Timeout(10)\n")
    assert len(findings) == 1 and "positional HTTP client timeout" in findings[0]
    embedded = 'RAW_HELPER = """client = httpx.Client(timeout=15)"""\n'
    assert scan_text(Path("docs") / "guides" / "example.py", embedded)


def test_waitable_positional_caps_and_nonblocking_join_methods_are_distinguished():
    source = (
        "worker.join(duration)\n"
        "proc.communicate(3)\n"
        "child = threading.Thread()\n"
        "child.join(mode)\n"
        '"".join(parts)\n'
    )
    findings = scan_text(Path("src/example.py"), source)
    assert len(findings) == 3


def test_timeout_command_options_and_multiline_curl_are_reported():
    source = (
        'sudo gtimeout --kill-after=2 "$RUN_TIMEOUT" command\n'
        "curl " + chr(92) + "\n"
        "  --connect-timeout 5 " + chr(92) + "\n"
        "  https://example.invalid\n"
    )
    assert len(scan_text(Path("scripts/build.sh"), source)) == 2
    assert scan_text(Path("scripts/build.sh"), "# timeout --kill-after=2 ignored\n") == []


def test_public_markdown_and_dockerfile_fences_are_scanned():
    markdown = (
        '```bash\ntimeout --kill-after=2 "$RUN_TIMEOUT" command\n```\n'
        "```dockerfile\n"
        "HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 CMD true\n"
        "```\n"
    )
    nested_markdown = Path("docs") / "guides" / "example.md"
    findings = scan_text(nested_markdown, markdown)
    assert len(findings) == 2
    assert findings[0].startswith(f"{nested_markdown}:2:")
    assert findings[1].startswith(f"{nested_markdown}:5:")
    indented_python = "1. Example\n   ```python\n   client = httpx.Client(timeout=5)\n   ```\n"
    nested = scan_text(nested_markdown, indented_python)
    assert len(nested) == 1 and "timeout argument" in nested[0]
    invalid_python = "```python\ndef broken(:\n    worker.join(duration)\n```\n"
    assert scan_text(nested_markdown, invalid_python)


def test_no_cap_waits_and_unbounded_http_are_allowed():
    source = """
with httpx.Client(timeout=None) as client:
    client.get(url)
thread.join()
proc.communicate()
await asyncio.wait({task})
"""
    assert scan_text(Path("src/example.py"), source) == []


def test_workflow_caps_are_reported():
    source = """
jobs:
  build:
    timeout-minutes: 5
    steps:
      - run: curl --max-time 10 https://example.invalid
"""
    findings = scan_text(Path(".github/workflows/build.yml"), source)
    assert len(findings) == 2
    assert any("workflow cap setting" in finding for finding in findings)
    assert any("shell time cap" in finding for finding in findings)


def test_shell_caps_are_reported():
    source = """
timeout 30 command
curl --connect-timeout 5 https://example.invalid
"""
    findings = scan_text(Path("scripts/build.sh"), source)
    assert len(findings) == 2


def test_tracked_runtime_and_test_files_contain_no_elapsed_time_caps():
    assert repository_findings(ROOT) == []


def test_hypothesis_disabled_deadline_is_unbounded_but_other_values_are_reported():
    assert scan_text(Path("tests/example.py"), "settings(deadline=None)\n") == []
    for value in ("1", "0", "timedelta(seconds=1)", "configured_deadline"):
        findings = scan_text(Path("tests/example.py"), f"settings(deadline={value})\n")
        assert len(findings) == 1
        assert "deadline keyword" in findings[0]


def test_allowlist_rejects_a_changed_or_second_cpu_exception(tmp_path):
    entries = json.loads((ROOT / ALLOWLIST).read_text())
    target = tmp_path / ALLOWLIST
    target.parent.mkdir(parents=True)
    cpu = next(e for e in entries if e["class"] == "sandbox-interpreter-cpu")
    for change in ({"pattern": cpu["pattern"] + " "}, {"path": "src/unifi_fabric/other.py"}):
        target.write_text(json.dumps([*entries[:-1], {**cpu, **change}]))
        assert check_allowlist(tmp_path)
    target.write_text(json.dumps([*entries, dict(cpu)]))
    assert check_allowlist(tmp_path)


def test_scope_alarm_socket_and_pytest_timeout_caps_are_reported():
    source = """
import pytest
from pytest import mark

pytestmark = pytest.mark.timeout(30)


@pytest.mark.timeout(5)
async def test_capped():
    async with asyncio.timeout(5):
        pass
    async with asyncio.timeout_at(loop.time() + 5):
        pass
    with anyio.fail_after(5):
        pass
    with trio.move_on_after(5):
        pass
    signal.alarm(5)
    signal.setitimer(signal.ITIMER_REAL, 5)
    sock.settimeout(5)
    socket.setdefaulttimeout(5)


@mark.timeout
def test_bare_mark():
    pass
"""
    findings = scan_text(Path("tests/test_example.py"), source)
    assert sum("pytest timeout mark" in finding for finding in findings) == 3
    for name in (
        "timeout",
        "timeout_at",
        "fail_after",
        "move_on_after",
        "alarm",
        "setitimer",
        "settimeout",
        "setdefaulttimeout",
    ):
        assert any(finding.endswith(f": {name} call") for finding in findings), name
    assert len(findings) == 11


@pytest.mark.parametrize(
    "api",
    [
        "asyncio.timeout",
        "asyncio.timeout_at",
        "anyio.fail_after",
        "anyio.move_on_after",
        "trio.fail_at",
        "trio.move_on_at",
    ],
)
@pytest.mark.parametrize("value", ["0", "0.0"])
def test_zero_scope_deadlines_are_reported(api, value):
    findings = scan_text(Path("src/example.py"), f"{api}({value})\n")
    assert len(findings) == 1
    assert findings[0].endswith(f": {api.rsplit('.', 1)[1]} call")


@pytest.mark.parametrize(
    "call",
    [
        "signal.alarm(0)",
        "signal.setitimer(signal.ITIMER_REAL, 0)",
        "sock.settimeout(0)",
        "socket.setdefaulttimeout(0)",
    ],
)
def test_zero_alarm_cancellation_and_nonblocking_sockets_are_allowed(call):
    assert scan_text(Path("src/example.py"), call) == []


def test_cap_calls_that_set_no_cap_are_allowed():
    source = """
async with asyncio.timeout(None):
    pass
with anyio.fail_after(None):
    pass
signal.alarm(0)
signal.setitimer(signal.ITIMER_REAL, 0)
sock.settimeout(None)
sock.settimeout(0)
socket.setdefaulttimeout(None)
"""
    assert scan_text(Path("src/example.py"), source) == []


def test_pytest_timeout_ini_options_are_reported():
    assert Path("pyproject.toml") in set(tracked_paths(ROOT))
    for text in (
        "[tool.pytest.ini_options]\ntimeout = 30\n",
        '[tool.pytest.ini_options]\naddopts = "-q --timeout=30"\n',
        '[tool.pytest.ini_options]\naddopts = ["--timeout", "30"]\n',
    ):
        assert scan_text(Path("pyproject.toml"), text), text
    assert scan_text(Path("pyproject.toml"), '[tool.pytest.ini_options]\naddopts = "-q"\n') == []
