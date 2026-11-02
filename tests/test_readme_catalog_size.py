"""The catalog runbook tools/list size table matches what the server actually sends.

Each row of the "Catalog size" table is re-measured over stdio: the server is started
with that ``UNIFI_TOOL_FAMILIES`` value, sent ``initialize`` and ``tools/list``, and the
UTF-8 JSON-RPC response line to ``tools/list`` is counted (1 KB = 1000 bytes, as the
catalog runbook states). The tool count must match exactly and the size within 2%, so a
description change that grows the catalog cannot leave the catalog runbook stale.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.changelog_section import current_release

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CATALOG = ROOT / "docs" / "CATALOG.md"
CHANGELOG = ROOT / "CHANGELOG.md"
MIGRATING = ROOT / "docs" / "MIGRATING-0.7.md"
TOLERANCE = 0.02

_ROW_RE = re.compile(r"^\| (unset \(all families\)|`([a-z_,]+)`) \| (\d+) \| ~(\d+) KB \|$", re.M)


def _table() -> list[tuple[str | None, int, int]]:
    text = CATALOG.read_text()
    start = text.index("| `UNIFI_TOOL_FAMILIES` | Tools | `tools/list` size |")
    end = text.find("\n\n", start)
    block = text[start : len(text) if end == -1 else end]
    rows = [(m.group(2), int(m.group(3)), int(m.group(4))) for m in _ROW_RE.finditer(block)]
    assert rows and rows[0][0] is None, "the table must start with the unset (all families) row"
    return rows


def _measure(
    families: str | None, mode: str = "full", *, compact_result: bool = False
) -> tuple[int, int]:
    """(tool count, bytes of the tools/list response line) over stdio."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env["UNIFI_API_KEY"] = "readme-size-test-key"
    env["UNIFI_TOOL_MODE"] = mode
    if families is not None:
        env["UNIFI_TOOL_FAMILIES"] = families
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "readme-size-test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    # stderr goes to a file (a pipe nobody drains could fill and block the server) so a
    # failed start reports why it failed instead of only that it did.
    stderr = tempfile.TemporaryFile()  # noqa: SIM115 - closed in the finally below
    proc = subprocess.Popen(  # noqa: S603 - this interpreter running the package's entry point
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr,
        env=env,
    )
    # Answer-driven (send, then read the reply): closing stdin early races the server's
    # shutdown against the tools/list reply. Wait for completion without a deadline.
    try:
        assert proc.stdin is not None and proc.stdout is not None

        def send(msg: dict) -> None:
            proc.stdin.write((json.dumps(msg) + "\n").encode())
            proc.stdin.flush()

        def reply(want: int) -> bytes:
            for line in iter(proc.stdout.readline, b""):
                if json.loads(line).get("id") == want:
                    return line.rstrip(b"\n")
            proc.wait()
            stderr.seek(0)
            tail = stderr.read()[-2000:].decode(errors="replace")
            cause = f"exited with code {proc.returncode}"
            raise AssertionError(
                f"{mode} server {cause} before answering request {want}; stderr tail:\n{tail}"
            )

        send(messages[0])
        reply(1)
        send(messages[1])
        send(messages[2])
        line = reply(2)
    finally:
        proc.kill()
        proc.wait()
        stderr.close()
    result = json.loads(line)["result"]
    assert result.get("nextCursor") is None, "tools/list is paginated; measure every page"
    size = len(line)
    if compact_result:
        size = len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return len(result["tools"]), size


def test_readme_prose_matches_the_table() -> None:
    text = README.read_text()
    _families, tools, kb = _table()[0]
    assert f"full mode advertises {tools} tools and its" in text
    assert f"`tools/list` response is roughly {kb} KB of JSON" in text


def test_changelog_catalog_size_matches_the_readme() -> None:
    section = current_release(CHANGELOG.read_text())[1]
    _families, tools, kb = _table()[0]
    found = re.findall(r"\((\d+) tools, about (\d+) KB of `tools/list`\)", section)
    assert found, "the CHANGELOG section states no catalog size (vacuous)"
    for found_tools, found_kb in found:
        assert (int(found_tools), int(found_kb)) == (tools, kb)


def test_changelog_body_shape_size_matches_the_generated_shapes() -> None:
    from tests.test_docs_currency import shape_totals

    section = " ".join((ROOT / "docs" / "MIGRATING-0.7.md").read_text().split())
    shaped, free, size = shape_totals()
    assert f"describe {shaped} pinned-spec body shapes" in section
    assert f"The other {free} object parameters" in section
    found = re.findall(r"The shapes are ([\d,]+) bytes of compact JSON", section)
    assert found, "the CHANGELOG section states no body-shape size (vacuous)"
    assert {int(n.replace(",", "")) for n in found} == {size}


@pytest.mark.parametrize(
    ("families", "tools", "kb"), _table(), ids=lambda v: str(v) if not isinstance(v, int) else None
)
def test_readme_tools_list_size_is_current(families: str | None, tools: int, kb: int) -> None:
    count, size = _measure(families)
    assert count == tools, (
        f"{families or 'all families'}: README says {tools} tools, server lists {count}"
    )
    measured_kb = size / 1000
    assert abs(measured_kb - kb) <= kb * TOLERANCE, (
        f"{families or 'all families'}: README says ~{kb} KB, tools/list is {measured_kb:.1f} KB "
        f"(>{TOLERANCE:.0%} off); update the README table"
    )


@pytest.mark.parametrize("mode", ["full", "discovery"])
def test_readme_mode_tools_list_size_is_current(mode: str) -> None:
    """Both mode rows retain the domain roster and state exact compact-result bytes."""
    text = CATALOG.read_text()
    start = text.index(
        "| `UNIFI_TOOL_MODE` | Advertised tools | Domain tools available | "
        "`tools/list` bytes | Size (1 KB = 1000 bytes) |"
    )
    end = text.find("\n\n", start)
    block = text[start : len(text) if end == -1 else end]
    rows = re.findall(
        r"^\| `(full|discovery)`(?: \(default\))? \| (\d+) \| (\d+) \| (\d+) \| ~\d+ KB \|$",
        block,
        re.M,
    )
    assert [row[0] for row in rows] == ["full", "discovery"]
    advertised, domains, documented_size = next(
        (int(count), int(available), int(size))
        for row_mode, count, available, size in rows
        if row_mode == mode
    )
    assert domains == _table()[0][1], "both modes must retain the full domain roster"
    count, size = _measure(None, mode, compact_result=True)
    assert count == advertised, (
        f"{mode}: README says {advertised} advertised tools, server lists {count}"
    )
    assert size == documented_size, (
        f"{mode}: README says {documented_size} bytes, tools/list is {size} bytes "
        "update the README mode table"
    )


def _generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_catalog_figures", ROOT / "scripts" / "gen_catalog_figures.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve annotations through sys.modules during class creation.
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return sys.modules[spec.name]


def test_catalog_figures_are_generated_and_drift_checked_in_ci() -> None:
    """One generator owns every figure, and the docs CI job runs its drift check."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    docs_job = workflow[workflow.index("\n  docs:\n") : workflow.index("\n  test:\n")]
    assert "scripts/gen_catalog_figures.py --check" in docs_job


CONFIGURATION_TEXT = (ROOT / "docs" / "CONFIGURATION.md").read_text()


def _block(text: str, gen, table: str) -> str:
    """The README family-count (``family``) or opt-out (``switch``) table."""
    header = gen.FAMILY_COUNT_HEADER if table == "family" else gen.SWITCH_TABLE_HEADER
    start, end = gen._table_block(text, header)
    return text[start:end]


def test_generator_rewrites_every_documented_figure(tmp_path, monkeypatch) -> None:
    """Synthetic figures replace every stated count and size; none is left hand-edited."""
    gen = _generator()
    readme, changelog = README.read_text(), CHANGELOG.read_text()
    catalog = CATALOG.read_text()
    families = gen.listed_families(catalog)
    fig = gen.Figures(
        tools=987,
        read_only=321,
        writes=666,
        confirm=19,
        full_kb=654,
        families={fam: (900 + i, 321_000 + i * 1000) for i, fam in enumerate(families)},
        modes={"full": (987, 654_321), "discovery": (7, 4_321)},
        shaped=77,
        free=66,
        shape_bytes=55_555,
        domains={d.label: 11 + i for i, d in enumerate(gen.DOMAINS)},
        family_counts={
            m.group(1): (500 + i, 50 + i)
            for i, m in enumerate(
                gen._FAMILY_COUNT_ROW_RE.finditer(_block(CONFIGURATION_TEXT, gen, "family"))
            )
        },
        hidden={
            m.group(2): 40 + i
            for i, m in enumerate(gen._SWITCH_ROW_RE.finditer(_block(readme, gen, "switch")))
        },
    )
    new_readme = gen.render_readme(readme, fig)
    new_changelog = gen.render_changelog(changelog, fig)
    new_catalog = gen.render_catalog(catalog, fig)
    new_coverage = gen.render_coverage(gen.COVERAGE.read_text(), fig)
    assert "19 write and action tools accept an optional `confirm`" in new_coverage
    assert "** 987 tools across Site Manager, Network, Protect, InnerSpace and more" in new_readme
    for path in (gen.DOCKER, gen.BUNDLE_README):
        source = path.read_text()
        stale, count = re.subn(
            r"(unifi-fabric-mcp-server[:=]+)\d+\.\d+\.\d+", r"\g<1>0.0.0", source
        )
        assert count
        updated = gen.render_install_versions(stale, "9.8.7")
        assert not re.search(r"unifi-fabric-mcp-server[:=]+0\.0\.0", updated)
        assert "9.8.7" in updated
    assert (
        gen.render_install_versions("ghcr.io/example/unifi-fabric-mcp-server:0.0.0", "9.8.7")
        == "ghcr.io/example/unifi-fabric-mcp-server:9.8.7"
    )
    rows = _ROW_RE.findall(new_catalog[new_catalog.index("| `UNIFI_TOOL_FAMILIES` |") :])
    assert [int(r[2]) for r in rows[: len(families)]] == [900 + i for i in range(len(families))]
    assert "full mode advertises 987 tools and its" in new_readme
    domain_rows = re.findall(r"^\| \*\*([^|]+)\*\* \| (\d+) \|", new_readme, re.M)
    assert domain_rows == [(d.label, str(11 + i)) for i, d in enumerate(gen.DOMAINS)]
    assert "`tools/list` response is roughly 654 KB of JSON" in new_readme
    assert "| `full` | 987 | 987 | 654321 | ~654 KB |" in new_catalog
    assert "| `discovery` (default) | 7 | 987 | 4321 | ~4 KB |" in new_catalog
    family_block = _block(gen.render_configuration(CONFIGURATION_TEXT, fig), gen, "family")
    family_rows = gen._FAMILY_COUNT_ROW_RE.findall(family_block)
    assert [row[0] for row in family_rows] == sorted(fig.family_counts)
    for i, row in enumerate(gen._FAMILY_COUNT_ROW_RE.finditer(family_block)):
        assert row.group(0).startswith(f"| `{row.group(1)}` | {500 + i} | {50 + i} | ")
    switch_rows = [
        m.group(0) for m in gen._SWITCH_ROW_RE.finditer(_block(new_readme, gen, "switch"))
    ]
    assert switch_rows[0] == "| none (default) | 40 | 947 |"
    assert len(switch_rows) == len(fig.hidden) == 8
    assert "the 77 pinned-spec request bodies" in " ".join(new_readme.split())
    count_re = re.compile(r"(?<![\w.-])(\d{2,3}) (?:MCP )?tools\b|(\d{2,3}) tool names\b")
    stated = {int(m.group(1) or m.group(2)) for m in count_re.finditer(new_readme)}
    assert _table()[0][1] not in stated, stated
    assert 987 in stated
    section = " ".join(current_release(new_changelog)[1].split())
    assert section.startswith("Highlights: 987 tools")
    assert "(987 tools, about 654 KB of `tools/list`)" in section
    assert "Tool annotations: the 321 read-only tools" in section
    assert "the 666 write tools advertise" in section
    # The body-shape figures live in the migration guide (render_migrating).
    migrating = " ".join(gen.render_migrating(MIGRATING.read_text(), fig).split())
    assert "Tool annotations: the 321 read-only tools" in migrating
    assert "the 666 write tools advertise" in migrating
    assert "describe 77 pinned-spec body shapes" in migrating
    assert "The other 66 object parameters" in migrating
    assert "The shapes are 55,555 bytes of compact JSON" in migrating
    quick_start = readme.index("### Choose your client")
    key_section = readme.index("### Get Your API Key", quick_start)
    stale_table = readme[quick_start:key_section].replace("0.7.0", "0.0.0")
    stale_readme = readme[:quick_start] + stale_table + readme[key_section:]
    regenerated = gen.render_readme(stale_readme, fig)
    assert "0.0.0" not in regenerated[quick_start : regenerated.index("### Get Your API Key")]
    assert "full mode uses about 654 KB" in regenerated
    assert "Discovery mode advertises 7 tools in about 4 KB" in regenerated
    assert "By default the client sees 7 discovery meta-tools" in regenerated
    assert "| Site Manager and fleet | 23 |" in new_readme
    assert (
        f"| Protect | {sum(v for k, v in fig.domains.items() if k.startswith('Protect'))} |"
        in new_readme
    )
    assert (
        f"| InnerSpace | {fig.domains['InnerSpace'] + fig.domains['Placement Snapshot']} |"
        in new_readme
    )
    assert "| Generic connector relay |" in new_readme
    evidence_marker = re.search(
        r"<!-- live-evidence: passed=(\d+) writes=(\d+) total=(\d+) "
        r"build=([0-9a-f]+) date=(\d{4}-\d{2}-\d{2}) -->",
        gen.COVERAGE.read_text(),
    )
    assert evidence_marker is not None
    passed, writes, total, build, date = evidence_marker.groups()
    assert (
        f"| Live-tested on a real console | {passed} of {total} passed on build `{build}`, {date} |"
        in new_readme
    )
    assert f"| Live write tools passed | {writes} on that build and date |" in new_readme
    assert "| Every tool runs in CI against a simulated upstream | 987 tools |" in new_readme
    evidence = tmp_path / "COVERAGE.md"
    evidence.write_text(
        "<!-- live-evidence: passed=42 writes=7 total=700 build=abcdef date=2026-01-02 -->"
    )
    with monkeypatch.context() as patch:
        patch.setattr(gen, "COVERAGE", evidence)
        changed = gen.render_readme(new_readme, fig)
    assert "42 of 700 passed on build `abcdef`, 2026-01-02" in changed
    assert "| Live write tools passed | 7 on that build and date |" in changed
    # Idempotent: rendering the generated text again changes nothing.
    assert gen.render_readme(new_readme, fig) == new_readme
    assert gen.render_catalog(new_catalog, fig) == new_catalog
    assert gen.render_changelog(new_changelog, fig) == new_changelog


def test_domain_table_is_generated_and_counts_every_tool_once() -> None:
    """Each README domain row is a rule in the generator; every tool lands in exactly one."""
    gen = _generator()
    inventory = gen.tool_inventory()
    counts = gen.domain_counts(inventory)
    assert sum(counts.values()) == len(inventory) == len({name for name, _m, _f in inventory})
    readme = README.read_text()
    rows = re.findall(r"^\| \*\*([^|]+)\*\* \| (\d+) \|", readme, re.M)
    assert [(label, int(n)) for label, n in rows] == list(counts.items())


def test_domain_counts_refuse_an_unclassified_or_stale_rule() -> None:
    """A tool no rule claims, a stale name, or a doubly-named tool fails loudly."""
    gen = _generator()
    inventory = [("a_tool", "some_module", "network"), ("b_tool", "server", "protect")]
    rules = (gen.Domain("A", modules=("some_module",)), gen.Domain("B", delegates=("protect",)))
    assert gen.domain_counts(inventory, rules) == {"A": 1, "B": 1}
    with pytest.raises(RuntimeError, match="fit no README domain"):
        gen.domain_counts([*inventory, ("c_tool", "other", "vpn")], rules)
    with pytest.raises(RuntimeError, match="unregistered tools"):
        gen.domain_counts(inventory, (*rules, gen.Domain("C", names=("gone_tool",))))
    with pytest.raises(RuntimeError, match="two domains"):
        gen.domain_counts(
            inventory,
            (gen.Domain("A", names=("a_tool",)), gen.Domain("B", names=("a_tool", "b_tool"))),
        )


def test_readme_smoke_test_protocol_version_is_the_negotiated_one() -> None:
    """The Docker initialize smoke test asks for, and reports, what the server answers."""
    text = (ROOT / "docs" / "DOCKER.md").read_text()
    requested = re.findall(r'"method":"initialize","params":\{"protocolVersion":"([^"]+)"', text)
    reported = re.findall(
        r'The `data:` line above it will contain a JSON object with `"protocolVersion":"([^"]+)"`',
        text,
    )
    assert requested and reported, "README smoke test not found"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env["UNIFI_API_KEY"] = "readme-protocol-test-key"
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": requested[0],
            "capabilities": {},
            "clientInfo": {"name": "readme-protocol-test", "version": "1"},
        },
    }
    # Answer-driven, as in _measure: closing stdin before the reply races the shutdown.
    proc = subprocess.Popen(  # noqa: S603 - this interpreter running the package's entry point
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write((json.dumps(message) + "\n").encode())
        proc.stdin.flush()
        result = None
        for line in iter(proc.stdout.readline, b""):
            answer = json.loads(line)
            if answer.get("id") == 1:
                result = answer["result"]
                break
    finally:
        proc.kill()
        proc.wait()
    assert result is not None, "the server exited before answering initialize"
    assert set(requested) == {result["protocolVersion"]}
    assert set(reported) == {result["protocolVersion"]}


def test_annotation_figures_match_the_registered_catalog():
    gen = _generator()
    reads, writes = gen.annotation_counts()
    from tests._tool_catalog import is_read, tools

    catalog = tools()
    assert reads == sum(is_read(tool) for tool in catalog)
    assert writes == sum(not is_read(tool) for tool in catalog)
    assert gen.confirm_parameter_count() == sum(
        "confirm" in (tool.parameters.get("properties") or {}) for tool in catalog
    )
