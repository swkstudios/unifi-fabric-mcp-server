"""Mechanical regression guard for elapsed-time caps."""

import json
import subprocess
from pathlib import Path

from scripts.check_no_timeouts import (
    ALLOWLIST,
    check_allowlist,
    repository_findings,
    scan_text,
    tracked_paths,
)

ROOT = Path(__file__).resolve().parents[1]


def test_allowlist_contains_only_the_two_approved_healthcheck_entries():
    entries = json.loads((ROOT / ALLOWLIST).read_text())
    assert {entry["path"] for entry in entries} == {"Dockerfile", "docs/TLS.md"}
    assert all(
        set(entry) == {"path", "pattern", "class", "citation", "verdict", "added"}
        for entry in entries
    )
    assert check_allowlist(ROOT) == []


def test_allowlist_rejects_unrecognized_private_verdict(tmp_path):
    entries = json.loads((ROOT / ALLOWLIST).read_text())
    entries[0]["verdict"] = "R-" + "2026-10-23-UNIFI-361-HEALTHCHECK-OTHER"
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
    procedure = Path("docs") / ("inter" + "nal") / ("testing" + "-procedure.md")
    if (ROOT / procedure).is_file():
        assert procedure in paths
    assert scan_text(Path(".github/lychee.toml"), "timeout = 12\n")


def test_qualified_timeout_aliases_and_embedded_helper_are_reported():
    findings = scan_text(Path("src/example.py"), "client = httpx2.Timeout(10)\n")
    assert len(findings) == 1 and "positional HTTP client timeout" in findings[0]
    embedded = 'RAW_HELPER = """client = httpx.Client(timeout=15)"""\n'
    assert scan_text(Path("docs") / ("inter" + "nal") / "example.py", embedded)


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
    internal_markdown = Path("docs") / ("inter" + "nal") / "example.md"
    findings = scan_text(internal_markdown, markdown)
    assert len(findings) == 2
    assert findings[0].startswith(f"{internal_markdown}:2:")
    assert findings[1].startswith(f"{internal_markdown}:5:")
    indented_python = "1. Example\n   ```python\n   client = httpx.Client(timeout=5)\n   ```\n"
    nested = scan_text(internal_markdown, indented_python)
    assert len(nested) == 1 and "timeout argument" in nested[0]
    invalid_python = "```python\ndef broken(:\n    worker.join(duration)\n```\n"
    assert scan_text(internal_markdown, invalid_python)


def test_demo_display_pacing_exemption_is_qualified_and_narrow():
    source = """
class Screen:
    def wait(self, seconds):
        end = time.monotonic() + seconds * PACE
        while time.monotonic() < end:
            time.sleep(0.09)
    def user(self):
        time.sleep(0.045 * PACE)
        self.wait(0.25)
class Session:
    async def tool(self, name, min_s):
        s = self.screen
        started = time.monotonic()
        while time.monotonic() - started < min_s * PACE:
            s.wait(0.09)
async def main():
    screen.wait(0.5)
"""
    assert scan_text(Path("scripts/demo/demo.py"), source) == []
    outside = source + "\ndef unrelated():\n    worker.join(1)\n"
    findings = scan_text(Path("scripts/demo/demo.py"), outside)
    assert len(findings) == 1 and "timed join call" in findings[0]


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
