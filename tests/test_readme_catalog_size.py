"""The catalog runbook tools/list size table matches what the server actually sends.

Each row of the "Catalog size" table is re-measured over stdio: the server is started
with that ``UNIFI_FAMILY_ALLOW`` value, sent ``initialize`` and ``tools/list``, and the
UTF-8 JSON-RPC response line to ``tools/list`` is counted (1 KB = 1000 bytes, as the
catalog runbook states). The tool count must match exactly and the size within 2%, so a
description change that grows the catalog cannot leave the catalog runbook stale.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.changelog_section import current_release, undated_in_flight

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CATALOG = ROOT / "docs" / "CATALOG.md"
CHANGELOG = ROOT / "CHANGELOG.md"
MIGRATING = ROOT / "docs" / "MIGRATING-0.7.md"
TOLERANCE = 0.02

_ROW_RE = re.compile(r"^\| (unset \(all families\)|`([a-z_,]+)`) \| (\d+) \| ~(\d+) KB \|$", re.M)


def _table() -> list[tuple[str | None, int, int]]:
    text = CATALOG.read_text()
    start = text.index("| `UNIFI_FAMILY_ALLOW` | Tools | `tools/list` size |")
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
        env["UNIFI_FAMILY_ALLOW"] = families
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


def test_readme_catalog_blocks_match_the_table() -> None:
    """The README's catalog blocks are exactly what the generator renders for the table's
    tool count (the count CI measures), so neither can state a different catalog size."""
    gen = _generator()
    blocks = gen._doc_blocks()
    text = README.read_text()
    _families, tools, _kb = _table()[0]
    fig = gen.Figures(
        tools=tools,
        read_only=0,
        writes=0,
        full_kb=0,
        families={},
        modes={},
        shaped=0,
        free=0,
        shape_bytes=0,
        domains={},
        family_counts={},
        hidden={},
    )
    rendered = gen.readme_blocks(fig)
    for name in ("catalog-headline", "how-it-works-catalog"):
        assert blocks.body(text, name) == rendered[name]() + "\n", name
    assert f"loading the entire {tools}-tool catalog" in text


def test_changelog_catalog_size_matches_the_readme() -> None:
    section = current_release()[1]
    _families, tools, kb = _table()[0]
    # Every release states its tool count in the Highlights lead (non-vacuous); a release
    # whose entries restate the full-mode size must state the README's size.
    lead = re.match(r"\s*Highlights: (\d+) tools \(", section)
    assert lead, "the CHANGELOG section states no catalog size (vacuous)"
    assert int(lead.group(1)) == tools
    found = re.findall(r"\((\d+) tools, about (\d+) KB of `tools/list`\)", section)
    for found_tools, found_kb in found:
        assert (int(found_tools), int(found_kb)) == (tools, kb)


def test_migrating_body_shape_size_matches_the_generated_shapes() -> None:
    from tests.test_docs_currency import shape_totals

    section = " ".join((ROOT / "docs" / "MIGRATING-0.7.md").read_text().split())
    shaped, free, size = shape_totals()
    assert f"describe {shaped} pinned-spec body shapes" in section
    assert f"The other {free} object parameters" in section
    found = re.findall(r"The shapes are ([\d,]+) bytes of compact JSON", section)
    assert found, "the migration guide states no body-shape size (vacuous)"
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
    assert "scripts/regen_docs.py --check" in docs_job


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
    # render_changelog leaves a DATED first section verbatim by design, which
    # test_generator_leaves_a_dated_first_section_untouched covers. This test is about the
    # IN-FLIGHT section, so exercise it undated whether or not the tree has been dated yet.
    # Without this the test passes only until the release is dated and then fails the
    # release itself: the 0.7.1 dating commit hit exactly that (CA-20261107-291).
    changelog = undated_in_flight(changelog)
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
        # The opt-out table lives in docs/CONFIGURATION.md (the README links to it).
        hidden={
            m.group(2): 40 + i
            for i, m in enumerate(
                gen._SWITCH_ROW_RE.finditer(_block(CONFIGURATION_TEXT, gen, "switch"))
            )
        },
    )
    new_readme = gen.render_readme(readme, fig)
    new_changelog = gen.render_changelog(changelog, fig)
    new_catalog = gen.render_catalog(catalog, fig)
    new_coverage = gen.render_coverage(gen.COVERAGE.read_text(), fig)
    assert "19 write and action tools accept an optional `confirm`" in new_coverage
    assert "loading the entire 987-tool catalog" in new_readme
    assert "**987 tools, loaded on demand.**" in new_readme
    assert "| Every tool runs in CI against a simulated upstream | 987 tools |" in new_readme
    # Registry level: every README block the generator owns holds exactly its rendering.
    blocks = gen._doc_blocks()
    rendered = gen.readme_blocks(fig)
    assert set(rendered) == set(blocks.names("README.md", gen.OWNER))
    for name, render in rendered.items():
        assert blocks.body(new_readme, name) == render() + "\n", name
    # A figure sentence reworded inside its block is restored, never silently left stale.
    for old, new in (
        ("loaded on demand.**", "served on demand.**"),
        ("than loading the entire", "than pulling the entire"),
    ):
        assert old in readme
        assert gen.render_readme(readme.replace(old, new), fig) == new_readme
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
    rows = _ROW_RE.findall(new_catalog[new_catalog.index("| `UNIFI_FAMILY_ALLOW` |") :])
    assert [int(r[2]) for r in rows[: len(families)]] == [900 + i for i in range(len(families))]
    assert "| `full` | 987 | 987 | 654321 | ~654 KB |" in new_catalog
    assert "| `discovery` (default) | 7 | 987 | 4321 | ~4 KB |" in new_catalog
    new_configuration = gen.render_configuration(CONFIGURATION_TEXT, fig)
    switch_rows = list(gen._SWITCH_ROW_RE.finditer(_block(new_configuration, gen, "switch")))
    assert [row.group(2) for row in switch_rows] == list(fig.hidden)
    for i, row in enumerate(switch_rows):
        assert row.group(0).endswith(f" | {40 + i} | {987 - 40 - i} |")
    family_block = _block(new_configuration, gen, "family")
    family_rows = gen._FAMILY_COUNT_ROW_RE.findall(family_block)
    assert [row[0] for row in family_rows] == sorted(fig.family_counts)
    for i, row in enumerate(gen._FAMILY_COUNT_ROW_RE.finditer(family_block)):
        assert row.group(0).startswith(f"| `{row.group(1)}` | {500 + i} | {50 + i} | ")
    count_re = re.compile(r"(?<![\w.-])(\d{2,3}) (?:MCP )?tools\b|(\d{2,3}) tool names\b")
    stated = {int(m.group(1) or m.group(2)) for m in count_re.finditer(new_readme)}
    assert _table()[0][1] not in stated, stated
    assert 987 in stated
    section = " ".join(current_release(new_changelog)[1].split())
    assert section.startswith("Highlights: 987 tools")
    # Only the in-flight section is rewritten; released sections keep their figures.
    released = changelog[changelog.index("\n## [", changelog.index("Highlights: ")) :]
    assert new_changelog.endswith(released)
    # The size and annotation figures are rewritten wherever an in-flight section states
    # them (a release that changes the catalog does), and are not required otherwise.
    full = (
        "# Changelog\n\n## [Unreleased]\n\n## [9.9.9]\n\nHighlights: 1 tools (1 added, 0 "
        "removed).\n\n### Changed\n\n- Full mode serves the catalog (1 tools, about 1 KB of "
        "`tools/list`).\n- Tool annotations: the 1 read-only tools advertise it; the 1 write "
        "tools advertise it.\n\n## [9.9.8] - 2026-01-01\n\nHighlights: 5 tools (5 added, 0 "
        "removed).\n"
    )
    section = " ".join(current_release(gen.render_changelog(full, fig))[1].split())
    assert section.startswith("Highlights: 987 tools")
    assert "(987 tools, about 654 KB of `tools/list`)" in section
    assert "Tool annotations: the 321 read-only tools" in section
    assert "the 666 write tools advertise" in section
    assert gen.render_changelog(full, fig).endswith("Highlights: 5 tools (5 added, 0 removed).\n")
    # Every release states its tool count: a section without it fails the generator.
    with pytest.raises(RuntimeError, match="Highlights"):
        gen.render_changelog(full.replace("Highlights: 1 tools", "Highlights: one tool"), fig)
    # The body-shape figures live in the migration guide (render_migrating).
    migrating = " ".join(gen.render_migrating(MIGRATING.read_text(), fig).split())
    assert "Tool annotations: the 321 read-only tools" in migrating
    assert "the 666 write tools advertise" in migrating
    assert "describe 77 pinned-spec body shapes" in migrating
    assert "The other 66 object parameters" in migrating
    assert "The shapes are 55,555 bytes of compact JSON" in migrating
    quick_start = readme.index("### 2. Connect your assistant")
    key_section = readme.index("### 3. Ask your first question", quick_start)
    stale_table = re.sub(
        r"(unifi-fabric-mcp-server[:=]+)\d+\.\d+\.\d+",
        r"\g<1>0.0.0",
        readme[quick_start:key_section],
    )
    stale_readme = readme[:quick_start] + stale_table + readme[key_section:]
    regenerated = gen.render_readme(stale_readme, fig)
    assert (
        "0.0.0"
        not in regenerated[quick_start : regenerated.index("### 3. Ask your first question")]
    )
    # Idempotent: rendering the generated text again changes nothing.
    assert gen.render_readme(new_readme, fig) == new_readme
    assert gen.render_catalog(new_catalog, fig) == new_catalog
    assert gen.render_changelog(new_changelog, fig) == new_changelog


def test_generator_repins_the_encoded_install_badge_versions() -> None:
    """The VS Code (URL-encoded) and Cursor (base64 config) badge pins follow the version."""
    gen = _generator()
    readme = README.read_text()
    current = gen.PUBLISHED_VERSION
    cursor = re.compile(r"cursor\.com/en/install-mcp\?[^\"\s)]*?config=([A-Za-z0-9_+/-]+=*)")
    payloads = cursor.findall(readme)
    assert payloads, "README must keep the Cursor install badge"
    assert f"unifi-fabric-mcp-server%3D%3D{current}" in readme
    assert gen.render_install_versions(readme, current) == readme
    updated = gen.render_install_versions(readme, "9.8.7")
    assert "unifi-fabric-mcp-server%3D%3D9.8.7" in updated
    assert f"%3D%3D{current}" not in updated
    new_payloads = cursor.findall(updated)
    assert len(new_payloads) == len(payloads)
    for old, new in zip(payloads, new_payloads, strict=True):
        config = json.loads(base64.urlsafe_b64decode(new + "=" * (-len(new) % 4)))
        assert "unifi-fabric-mcp-server==9.8.7" in config["command"]
        assert old.endswith("=") == new.endswith("=")
    assert gen.render_install_versions(updated, current) == readme


@pytest.mark.parametrize("suffix", ["rc1", ".post1", ".1", "-dev.1"])
def test_suffixed_encoded_pins_are_rerendered_so_check_fails(suffix: str) -> None:
    """A hand-edited suffix on either encoded pin is replaced, never silently kept."""
    gen = _generator()
    readme = README.read_text()
    current = gen.PUBLISHED_VERSION
    vscode = f"unifi-fabric-mcp-server%3D%3D{current}"
    assert vscode in readme
    stale_vscode = readme.replace(vscode, vscode + suffix)
    assert gen.render_install_versions(stale_vscode, current) == readme
    cursor = re.compile(r"(cursor\.com/en/install-mcp\?[^\"\s)]*?config=)([A-Za-z0-9_+/-]+=*)")
    match = cursor.search(readme)
    assert match
    config = base64.b64decode(match[2]).decode()
    stale_config = config.replace(f"=={current}", f"=={current}{suffix}")
    assert stale_config != config
    stale_payload = base64.b64encode(stale_config.encode()).decode()
    stale_cursor = readme.replace(match[2], stale_payload)
    assert gen.render_install_versions(stale_cursor, current) == readme


def test_domain_table_is_generated_and_counts_every_tool_once() -> None:
    """Each README domain row is a rule in the generator; every tool lands in exactly one."""
    gen = _generator()
    inventory = gen.tool_inventory()
    counts = gen.domain_counts(inventory)
    assert sum(counts.values()) == len(inventory) == len({name for name, _m, _f in inventory})
    readme = README.read_text()
    if gen.DOMAIN_TABLE_HEADER in readme:
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


def test_generator_leaves_a_dated_first_section_untouched() -> None:
    """A first numbered CHANGELOG section with a date has shipped: its figures stay verbatim."""
    gen = _generator()
    fig = gen.Figures(
        tools=987,
        read_only=321,
        writes=666,
        full_kb=654,
        families={},
        modes={},
        shaped=0,
        free=0,
        shape_bytes=0,
        domains={},
        family_counts={},
        hidden={},
    )
    released = (
        "# Changelog\n\n## [Unreleased]\n\n## [9.9.9] - 2026-02-02\n\nHighlights: 1 tools "
        "(1 added, 0 removed).\n\n### Changed\n\n- Full mode serves the catalog (1 tools, "
        "about 1 KB of `tools/list`).\n\n## [9.9.8] - 2026-01-01\n\nHighlights: 5 tools "
        "(5 added, 0 removed).\n"
    )
    assert gen.render_changelog(released, fig) == released
    in_flight = released.replace("## [9.9.9] - 2026-02-02", "## [9.9.9]")
    assert "Highlights: 987 tools" in gen.render_changelog(in_flight, fig)


def test_changelog_regenerates_added_and_removed_counts():
    gen = _generator()
    fig = gen.Figures(
        tools=987,
        read_only=321,
        writes=666,
        full_kb=654,
        families={},
        modes={},
        shaped=0,
        free=0,
        shape_bytes=0,
        domains={},
        family_counts={},
        hidden={},
        catalog_delta=(2, 1),
    )
    text = "# Changelog\n\n## [9.9.9]\n\nHighlights: 1 tools (0 added, 0 removed).\n"
    assert "Highlights: 987 tools (2 added, 1 removed)" in gen.render_changelog(text, fig)
