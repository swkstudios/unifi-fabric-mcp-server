"""The catalog generators document the complete catalog, whatever the caller's settings."""

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import gen_tools_doc as gen
from tests.runtime_catalog import runtime_tool_count

ROOT = Path(__file__).resolve().parents[1]


@functools.cache
def _tool_count() -> int:
    """The runtime tool count, computed on first use (never at import: see test_collect_guard)."""
    return runtime_tool_count()


#: Each setting shrinks the registered catalog when the server imports under it.
NARROWING = {
    "UNIFI_EXCLUDE": "family:protect",
    "UNIFI_FAMILY_ALLOW": "network",
    "UNIFI_TOOL_MODE": "discovery",
}


def _run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **NARROWING}
    return subprocess.run(  # noqa: S603 - fixed repo-local script
        [sys.executable, str(ROOT / "scripts" / script), *args],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_catalog_environ_drops_catalog_settings_and_keeps_the_rest():
    env = gen.catalog_environ({**NARROWING, "MCP_X": "1", "FASTMCP_Y": "2", "PATH": "/bin"})
    assert env == {
        "PATH": "/bin",
        "UNIFI_API_KEY": "catalog-generator-placeholder-key",
        "UNIFI_TOOL_MODE": "full",
    }


def test_runtime_tools_restore_the_caller_environment(monkeypatch):
    import asyncio

    for name, value in NARROWING.items():
        monkeypatch.setenv(name, value)
    before = dict(os.environ)
    assert len(asyncio.run(gen._runtime_tools())) == _tool_count()
    assert dict(os.environ) == before


def test_tools_doc_and_schema_checks_pass_under_narrowing_settings():
    for script in ("gen_tools_doc.py", "gen_tool_input_schemas.py"):
        result = _run(script, "--check")
        assert result.returncode == 0, (script, result.stderr)


def test_api_source_counts_report_the_complete_catalog():
    result = _run("api_source_counts.py", "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["total"] == _tool_count()


def test_discovery_queries_cover_the_complete_catalog():
    program = (
        "import asyncio, sys; "
        f"sys.path.insert(0, {str(ROOT / 'scripts')!r}); "
        "import gen_discovery_queries as g; "
        "print(len(asyncio.run(g.generate())['tools']))"
    )
    result = subprocess.run(  # noqa: S603 - fixed program, repo-local path
        [sys.executable, "-c", program],
        cwd=ROOT,
        env={**os.environ, **NARROWING},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert int(result.stdout) == _tool_count()


def test_full_mode_catalog_ignores_narrowing_settings(monkeypatch):
    sys.path.insert(0, str(ROOT / "scripts"))
    from mcp_navigation import full_mode_catalog

    for name, value in NARROWING.items():
        monkeypatch.setenv(name, value)
    assert len(full_mode_catalog(str(ROOT / "src"))) == _tool_count()


@pytest.fixture
def coverage_copy(tmp_path, monkeypatch):
    """A stand-in for docs/COVERAGE.md whose release-count phrase is stale."""
    coverage = tmp_path / "COVERAGE.md"
    coverage.write_text("Covers this release's 1 tools.\n")
    monkeypatch.setattr(gen, "RELEASE_COUNT_FILES", (coverage,))
    monkeypatch.setattr(gen, "DOCS_PATH", tmp_path / "TOOLS.md")
    return coverage


def test_preview_output_leaves_the_release_counts_alone(coverage_copy, tmp_path, monkeypatch):
    preview = tmp_path / "preview.md"
    monkeypatch.setattr(sys, "argv", ["gen_tools_doc.py", "--output", str(preview)])
    assert gen.main() == 0
    assert preview.read_text().startswith("#")
    assert coverage_copy.read_text() == "Covers this release's 1 tools.\n"


def test_default_output_rewrites_the_release_counts(coverage_copy, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["gen_tools_doc.py"])
    assert gen.main() == 0
    assert coverage_copy.read_text() == f"Covers this release's {_tool_count()} tools.\n"


def _scope_tools(markdown: str) -> list[str]:
    paragraph = next(line for line in markdown.splitlines() if line.startswith("**Scope.**"))
    typed = paragraph[paragraph.index("these typed tools: ") : paragraph.index(". Each typed")]
    return re.findall(r"`([a-z_]+)`", typed)


def test_connector_scope_lists_exactly_the_typed_writes_the_switch_hides(monkeypatch):
    import asyncio

    from unifi_fabric import families
    from unifi_fabric.read_only_tools import _is_read_tool

    tools = asyncio.run(gen._runtime_tools())
    index = families.build_family_index()
    hidden = sorted(
        tool.name
        for tool in tools
        if tool.name in families.connector_write_tools()
        and not _is_read_tool(tool)
        and tool.name != "fabric_connector_get"
        and index.get(tool.name) != "connector"
    )
    assert hidden and sorted(_scope_tools((ROOT / "docs" / "TOOLS.md").read_text())) == hidden

    # The list follows the generated table, not prose kept by hand.
    narrowed = families.connector_write_tools() - {hidden[0]}
    monkeypatch.setattr(families, "connector_write_tools", lambda: narrowed)
    assert _scope_tools(gen.render_markdown(tools)) == hidden[1:]
