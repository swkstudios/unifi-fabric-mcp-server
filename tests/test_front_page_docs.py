"""The public front page and community files: what a stranger sees, and that it is true.

Each test pins one finding of the final docs review (E-nn: the Claude reviewer; CX-n: the
Codex reviewer; I-n: its improvements) to the code or to the file that must carry it.
Statements about behaviour were checked by running the server (see the per-test notes);
these tests keep them from drifting.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tests.changelog_section import current_release, sections

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
README = ROOT / "README.md"
DOCS = ROOT / "docs"
PUBLIC_REPO = "https://github.com/swkstudios/unifi-fabric-mcp-server"

# Markdown files a visitor can reach from GitHub's front page (internal docs ship nowhere).
PUBLIC_MD = [
    README,
    ROOT / "CHANGELOG.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "AGENTS.md",
    ROOT / "CLAUDE.md",
    ROOT / "PRIVACY.md",
    ROOT / "LAST_AUDITED.md",
    ROOT / "CODE_OF_CONDUCT.md",
    ROOT / "ACCESSIBILITY.md",
    ROOT / ".github" / "SECURITY.md",
    ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
    *sorted(DOCS.glob("*.md")),
    *sorted((ROOT / "plugins").glob("*/README.md")),
]
PUBLIC_MD = [p for p in PUBLIC_MD if p.exists()]  # a missing required file fails its own test


def _text(path: Path) -> str:
    return path.read_text()


def _runtime_tool_count() -> int:
    from unifi_fabric import server

    return len(server.mcp._local_provider._components)  # noqa: SLF001 - registered catalog


def _changed_input_schema_count() -> int:
    from tests.test_changelog_input_schemas import _diff

    return len(_diff()[3])


def _added_removed_counts() -> tuple[int, int]:
    """Tools added to and removed from the 0.6.2 catalog, recomputed from the registry."""
    from tests.test_changelog_input_schemas import _diff

    old, new = _diff()[:2]
    return len(set(new) - set(old)), len(set(old) - set(new))


def _flat(path: Path) -> str:
    """The file's text as one line, without blockquote or comment markers between lines."""
    lines = (re.sub(r"^\s*(?:>|#)\s?", "", ln) for ln in _text(path).splitlines())
    return " ".join(" ".join(lines).split())


def _prose(text: str) -> str:
    """The text with fenced code blocks removed (links and headings inside them are examples)."""
    return re.sub(r"^```.*?^```[^\n]*$", "", text, flags=re.M | re.S)


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lowercase, drop punctuation, spaces to hyphens."""
    heading = re.sub(r"[`*]", "", heading.strip().lower())
    heading = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    return re.sub(r"[^\w\- ]", "", heading).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out: set[str] = set(re.findall(r'<a id="([^"]+)"\s*></a>', _prose(_text(path))))
    for line in _prose(_text(path)).splitlines():
        m = re.match(r"^#{1,6}\s+(.*?)\s*\Z", line)
        if not m:
            continue
        slug = _slug(m.group(1))
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        out.add(slug if n == 0 else f"{slug}-{n}")
    return out


_LINK = re.compile(r"(?<!\\)\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")


def test_every_relative_link_and_anchor_resolves():
    """E-03: README linked ``#claude-desktop`` (the heading is "Use with Claude Desktop")."""
    bad = []
    for path in PUBLIC_MD:
        for m in _LINK.finditer(_prose(_text(path))):
            target = m["target"]
            if re.match(r"[a-z][a-z0-9+.-]*:", target):  # http(s), mailto
                continue
            file_part, _, frag = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            where = f"{path.relative_to(ROOT)}: {target}"
            if not dest.exists():
                bad.append(f"{where} (no such file)")
            elif frag and dest.suffix == ".md" and frag not in _anchors(dest):
                bad.append(f"{where} (no such heading)")
    assert not bad, "\n".join(bad)


# -------------------------------------------------------------------- the first screen
def _readme_lines() -> list[str]:
    return _text(README).splitlines()


def test_hook_demo_and_quick_start_come_first():
    """E-21/E-23/E-24/I-1: the install path starts in the first screens, under one hook."""
    lines = _readme_lines()
    first_h2 = next(i for i, ln in enumerate(lines) if ln.startswith("## "))
    head = "\n".join(lines[:first_h2])
    assert "![Demo:" in head and "docs/assets/demo.gif" in head, "demo belongs under the hook"
    assert "scripts/demo/README.md" in head
    assert "Manage your entire UniFi network remotely from any AI assistant" in head
    assert "UniFi Fabric API in Ubiquiti's cloud" in head
    quick = next(i for i, ln in enumerate(lines) if ln == "## Quick Start")
    assert quick < 90, f"Quick Start starts at line {quick + 1}; a visitor must not scroll for it"
    for heading in ("## Architecture", "## What is MCP?", "## Use Cases"):
        at = lines.index(heading) if heading in lines else None
        assert at is None or at > quick, f"{heading} sits above Quick Start"
    # one hook: the old stacked intro paragraphs are gone
    assert "Cloud-first UniFi management for AI agents" not in head
    assert "An MCP (Model Context Protocol) server that exposes" not in head


def test_readme_has_a_short_table_of_contents():
    """E-25: a manual contents line near the top, linking the main sections."""
    lines = _readme_lines()
    first_h2 = next(i for i, ln in enumerate(lines) if ln.startswith("## "))
    head = "\n".join(lines[:first_h2])
    for anchor in (
        "#quick-start",
        "#example-prompts",
        "#available-tools",
        "#configuration",
        "#troubleshooting",
    ):
        assert f"]({anchor})" in head, anchor


def test_readme_is_shorter_than_it_was():
    """E-21/I-2: long reference material lives in docs/, linked from the README."""
    assert len(_readme_lines()) <= 1100, len(_readme_lines())
    for name in ("CONFIGURATION", "AUTH-TLS", "PAGINATION", "RETRY", "COVERAGE"):
        assert (DOCS / f"{name}.md").is_file(), name
        assert f"docs/{name}.md" in _text(README), f"README does not link docs/{name}.md"


def _client_table() -> list[str]:
    text = _text(README)
    start = text.index("### Choose your client")
    block = text[start : text.index("\n### ", start + 5)]
    return [ln for ln in block.splitlines() if ln.startswith("|")]


def test_choose_your_client_table_fits_a_phone():
    """The client table keeps two columns and includes the supported clients."""
    rows = _client_table()
    assert len(rows) >= 9, rows  # header, rule, seven clients
    for row in rows:
        cells = [c for c in row.strip("|").split("|")]
        assert len(cells) == 2, row

    flat = "\n".join(rows)
    for client in (
        "Claude Code",
        "Claude Desktop",
        "Codex",
        "Antigravity",
        "Gemini CLI",
        "ChatGPT",
    ):
        assert client in flat, client


def test_quick_start_is_three_steps_and_names_the_key_step():
    text = _text(README)
    block = text[text.index("## Quick Start") : text.index("### Choose your client")]
    steps = re.findall(r"^\d\. ", block, re.M)
    assert steps == ["1. ", "2. ", "3. "], steps
    assert "(#get-your-api-key)" in block


def test_pypi_badge_is_in_the_badge_row():
    """E-26: the PyPI badge (live once the package is published)."""
    head = "\n".join(_readme_lines()[:12])
    assert (
        "[![PyPI](https://img.shields.io/pypi/v/unifi-fabric-mcp-server)]"
        "(https://pypi.org/project/unifi-fabric-mcp-server/)"
    ) in head


# ------------------------------------------------------------- the demo (approved v2)
def test_demo_assets_and_sources_ship():
    for rel in (
        "docs/assets/demo.mp4",
        "docs/assets/demo.gif",
        "scripts/demo/README.md",
        "scripts/demo/demo.py",
        "scripts/demo/mock_api.py",
        "scripts/demo/compose.py",
        "scripts/demo/run.sh",
        "scripts/demo/demo.tape",
        "scripts/demo/fixtures.json",
        "scripts/demo/hallway.jpg",
        "scripts/demo/make_hallway.py",
        "scripts/demo/background.png",
    ):
        assert (ROOT / rel).is_file(), rel
    assert (ROOT / "docs/assets/demo.gif").stat().st_size < 3_000_000
    assert (ROOT / "docs/assets/demo.mp4").read_bytes()[4:8] == b"ftyp"
    assert (ROOT / "docs/assets/demo.gif").read_bytes()[:6] in (b"GIF87a", b"GIF89a")


def test_demo_is_synthetic_and_dry_run():
    """The mock refuses writes, the client runs the real server dry-run (README says so)."""
    readme = _text(ROOT / "scripts/demo/README.md")
    assert "UNIFI_DRY_RUN=1" in readme and "synthetic" in readme
    demo = _text(ROOT / "scripts/demo/demo.py")
    assert "UNIFI_DRY_RUN" in demo and "UNIFI_API_BASE_URL" in demo
    assert "127.0.0.1" in _text(ROOT / "scripts/demo/mock_api.py")


# --------------------------------------------------------- Claude Code install (E-01, E-04)
def test_claude_code_config_location_is_not_settings_json():
    """E-01/CX-2: ``mcpServers`` in ``~/.claude/settings.json`` is ignored.

    Verified with Claude Code 2.1.296: ``mcpServers`` in settings.json -> ``claude mcp
    list`` shows nothing; the same JSON in a project ``.mcp.json`` -> "Pending approval".
    """
    for path in (README, ROOT / "plugins/claude/README.md"):
        assert "settings.json" not in _text(path) or "mcpServers" not in _text(path), path
    text = _text(README)
    assert "~/.claude/settings.json" not in text
    assert "`.mcp.json`" in text
    assert "`.mcp.json`" in _text(DOCS / "DOCKER.md")
    assert "claude mcp add --scope user" in text
    assert "~/.claude.json" in text


def test_read_only_quick_start_connects_an_assistant():
    """E-02/CX-1: running ``uvx`` in a terminal only starts a stdio server waiting on stdin."""
    text = _text(README)
    assert "then ask your assistant" not in text
    assert "unifi-fabric-mcp --version" in text
    assert f"-e UNIFI_READ_ONLY=1 -- uvx --from unifi-fabric-mcp-server=={VERSION}" in text


def test_claude_marketplace_lists_the_plugin():
    """E-04: ``/plugin marketplace add`` works; Codex still reads its own marketplace."""
    data = json.loads(_text(ROOT / ".claude-plugin/marketplace.json"))
    assert data["name"] == "unifi-fabric"
    assert data["owner"]["name"]
    (entry,) = data["plugins"]
    assert entry["name"] == "unifi-fabric" and entry["source"] == "./plugins/claude"
    manifest = json.loads(_text(ROOT / "plugins/claude/.claude-plugin/plugin.json"))
    assert manifest["name"] == entry["name"]
    assert "version" not in entry, "the plugin manifest owns the version"
    assert (ROOT / ".agents/plugins/marketplace.json").is_file()  # Codex prefers this one
    for path in (ROOT / "plugins/claude/README.md", README):
        text = _text(path)
        assert f"/plugin marketplace add {PUBLIC_REPO.split('github.com/')[1]}" in text, path
        assert "/plugin install unifi-fabric@unifi-fabric" in text, path


def test_claude_plugin_readme_states_its_prerequisites():
    """CX-6, CX-LOW: key precedence and the Claude Code version the manifest was validated on."""
    text = " ".join(_text(ROOT / "plugins/claude/README.md").split())
    assert "A nonempty `UNIFI_API_KEYS` overrides the single plugin key" in text
    assert "validated with Claude Code 2.1.296" in text
    assert "Update Claude Code before installing" in text
    assert "../../README.md#use-with-claude-desktop" in text
    assert "#claude-desktop)" not in text


def test_claude_plugin_audit_log_limitation_is_disclosed():
    """CX-LOW: audit logging is best-effort (checked: an unwritable path logs a warning only)."""
    for path in (README, ROOT / "PRIVACY.md", ROOT / "plugins/claude/README.md"):
        assert "best-effort" in _text(path), path


def test_codex_readme_quotes_the_real_no_key_message():
    """E-06/CX-LOW: the quoted startup error is what the server prints."""
    env = {"PATH": "/usr/bin:/bin", "HOME": str(ROOT), "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(  # noqa: S603 - this interpreter, the package's own entry point
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    message = proc.stderr.strip().splitlines()[-1]
    assert message.startswith("UNIFI_API_KEY is not set"), proc.stderr
    text = " ".join(_text(ROOT / "plugins/codex/README.md").split())
    assert message in text
    assert "No API key configured" not in text


# ------------------------------------------------------------------- read-only wording
def test_read_only_refusal_names_where_to_unset_it_for_every_install():
    """E-05: the refusal named only a docker-compose file, useless to uvx and plugin users."""
    from unifi_fabric import read_only

    msg = read_only.read_only_message("PUT")
    assert "UNIFI_READ_ONLY" in msg
    assert "docker-compose" in msg
    assert "`env`" in msg, "the MCP client's env block"
    assert "Read-only mode" in msg, "the plugin option and the README section"
    text = " ".join(_text(README).split())
    assert "names the variable and its value" in text
    assert "unset `UNIFI_READ_ONLY` in the client config's `env`" in text


# --------------------------------------------------------------------- links to the spec
def test_oauth_doc_links_a_live_authorization_spec():
    """E-07: spec.modelcontextprotocol.io no longer answers (SSL EOF)."""
    text = _text(DOCS / "AUTH-OAUTH.md")
    assert "spec.modelcontextprotocol.io" not in text
    assert "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization" in text
    assert "MCP-2025-03-26" not in text


def test_no_doc_cites_the_old_network_version():
    """E-08: everything is pinned to Network 10.6.106 (spec baseline, LAST_AUDITED.md)."""
    for path in PUBLIC_MD:
        assert "10.3.58" not in _text(path), path
    assert "v10.6.106/connectorput" in _text(README)


def test_stale_placeholder_and_template_examples_are_gone():
    """E-09, E-10."""
    assert "Tier-3" not in _text(README)
    bug = _text(ROOT / ".github/ISSUE_TEMPLATE/bug_report.md")
    assert "v0.5.0" not in bug
    assert f"v{VERSION} or ghcr.io/swkstudios/unifi-fabric-mcp-server:{VERSION}" in bug


def test_tested_against_figures_say_when_they_were_measured():
    """E-11: the figures come from the last live sweep, and say so with its date."""
    text = _text(DOCS / "COVERAGE.md")
    marker = re.search(
        r"live-evidence: passed=\d+ writes=\d+ total=\d+ build=([0-9a-f]+) "
        r"date=(\d{4}-\d{2}-\d{2})",
        text,
    )
    assert marker
    readme = _text(README)
    assert f"build `{marker[1]}`, {marker[2]}" in readme


def test_no_yaml_inside_a_bash_fence():
    """E-12: a Compose YAML block in a ``bash`` fence is not copy-pasteable."""
    bad = []
    for path in PUBLIC_MD:
        for m in re.finditer(r"^```(?:bash|sh)\n(.*?)^```", _text(path), re.M | re.S):
            if re.search(r"^services:\s*$", m.group(1), re.M):
                bad.append(str(path.relative_to(ROOT)))
    assert not bad, bad


def test_contributing_and_agents_md_follow_the_public_workflow():
    """E-13, CX-LOW: no internal branch name; changelog rule matches the CHANGELOG."""
    contrib = _text(ROOT / "CONTRIBUTING.md")
    assert "work off `dev`" not in contrib
    assert "Internal maintainers" not in contrib
    for path in (ROOT / "CONTRIBUTING.md", ROOT / "AGENTS.md"):
        text = " ".join(_text(path).split())
        assert "in-flight version section" in text, path
        assert "date that version heading" in text, path


def test_contributor_changelog_instructions_name_the_fragment_process():
    """The PR template and CONTRIBUTING.md say what changelog.d/README.md and CI enforce.

    A PR adds a ``changelog.d`` fragment and leaves ``CHANGELOG.md`` alone; neither page
    may send a contributor to ``## [Unreleased]``, where a stray entry would recur.
    """
    for path in (ROOT / ".github/PULL_REQUEST_TEMPLATE.md", ROOT / "CONTRIBUTING.md"):
        text = " ".join(_text(path).split())
        assert "[Unreleased]" not in text, path
        assert "`changelog.d` fragment" in text, path
        assert "`skip-changelog` label" in text, path
        for suffix in (".added.md", ".changed.md", ".fixed.md", ".security.md"):
            assert f"`{suffix}`" in text, (path, suffix)
    contrib = " ".join(_text(ROOT / "CONTRIBUTING.md").split())
    # The public copy has no fold script and must not name it (the name is built so the
    # public tree carries no reference to the removed file).
    fold = "_".join(("regenerate", "changelog"))
    if (ROOT / "scripts" / f"{fold}.py").exists():
        assert f"python3 scripts/{fold}.py" in contrib
    else:
        assert fold not in contrib
    assert "Do not edit `CHANGELOG.md`" in contrib


def test_claude_md_imports_the_agents_guide():
    """CLAUDE.md does not duplicate the guide: Claude Code imports AGENTS.md."""
    text = _text(ROOT / "CLAUDE.md")
    assert "\n@AGENTS.md\n" in text
    assert len(text.splitlines()) < 10


def test_agents_md_describes_the_multikey_tests_that_exist():
    """CX-LOW: the 'known gap' (strict xfail) is closed; the routing tests exist and pass."""
    text = _text(ROOT / "AGENTS.md")
    assert "Known gap" not in text and "strict-xfail" not in text
    assert "Registry.resolve_key_for_host" in text
    assert "tests/test_multikey_routing.py" in text
    routing = _text(ROOT / "tests/test_multikey_routing.py")
    assert "xfail" not in routing


def test_last_audited_does_not_promise_automatic_markdown_updates():
    """CX-LOW: ``--update-baseline`` rewrites the JSON baseline only."""
    text = " ".join(_text(ROOT / "LAST_AUDITED.md").split())
    assert "updated whenever" not in text
    assert "updates only the JSON baseline" in text
    assert "tests/fixtures/spec_drift/baseline_snapshot.json" in text


# ------------------------------------------------------------------------------ CHANGELOG
def test_changelog_has_an_unreleased_heading_above_the_in_flight_version():
    """E-14: ``## [Unreleased]`` sits above the in-flight version section."""
    names = [name for name, _h, _b in sections(_text(ROOT / "CHANGELOG.md"))]
    assert names[0] == "Unreleased" and names[1] == VERSION, names[:3]
    headings = {name: h for name, h, _b in sections(_text(ROOT / "CHANGELOG.md"))}
    # The release step dates the in-flight heading at ship; every older release is dated.
    assert re.fullmatch(
        rf"## \[{re.escape(VERSION)}\](?: - \d{{4}}-\d{{2}}-\d{{2}})?", headings[VERSION]
    ), headings[VERSION]
    assert re.fullmatch(r"## \[0\.6\.2\] - \d{4}-\d{2}-\d{2}", headings["0.6.2"])


def test_changelog_released_sections_are_the_public_text():
    """E-15/CX-LOW: released history is byte-identical to the published v0.6.2 tag.

    ``tests/fixtures/changelog_released_v0.6.2.md.gz`` is the suffix of the public tag's
    CHANGELOG.md that begins at ``## [0.6.2]``; everything older is unchanged since.
    """
    # Stored gzipped: the published text quotes public issue numbers, which the mirror
    # verifier (rightly) refuses to find as plain text in shipped test files.
    fixture = ROOT / "tests/fixtures/changelog_released_v0.6.2.md.gz"
    stored = gzip.decompress(fixture.read_bytes())
    assert hashlib.sha256(stored).hexdigest() == (
        "167a3e1548bfabe6c7a82aa2a9ed739c314b15fa618e0e5a16a2fd910060f708"
    )
    current = (ROOT / "CHANGELOG.md").read_bytes()
    cut = current.index(b"## [0.6.2] - ")
    assert current[cut:] == stored


def test_release_highlights_open_the_in_flight_section():
    """I-6: the release body starts with a summary instead of a very long first bullet."""
    version, body = current_release()
    assert version == VERSION
    lead = body.strip().splitlines()[0]
    assert lead.startswith("Highlights: ")
    added, removed = _added_removed_counts()
    for part in (
        f"{_runtime_tool_count()} tools",
        f"{added} added, {removed} removed",
        "UNIFI_READ_ONLY",
        "Claude Code, Claude Desktop, Codex, Antigravity and Gemini CLI",
        f"{_changed_input_schema_count()} tools",
        "Breaking",
    ):
        assert part in lead, part
    assert body.index("Highlights: ") < body.index("### Added")


def test_changelog_describes_homebrew_as_a_template():
    """CX-LOW: the formula is a template (zero checksum); no tap exists yet."""
    version_body = " ".join(current_release()[1].split())
    assert "Homebrew formula template" in version_body
    assert "A maintainer must set the release-archive checksum and publish a tap" in version_body


def test_breaking_entries_link_to_the_tag_pinned_tool_catalog():
    """Release-body links resolve independently of a repository page."""
    text = _text(ROOT / "CHANGELOG.md")
    catalog = "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/docs/TOOLS.md#tool-categories"
    for marker in (
        "Breaking: host and site resolution never guess;",
        "Breaking: write tools drop server-added `_` keys;",
    ):
        entry = next(line for line in text.splitlines() if marker in line)
        assert catalog in entry, marker


def test_active_release_docs_do_not_claim_workflow_timeouts():
    """Current release documents do not promise workflow time limits."""
    version, body = current_release()
    assert version == VERSION
    assert "timeout-minutes" not in body
    assert "hang-stop" not in body

    migration = _text(DOCS / "MIGRATING-0.7.md")
    assert "### change-082" not in migration
    assert "Every GitHub Actions job has a hang-stop" not in migration

    # Keep the older 0.6.2 history intact when removing an active-release claim.
    changelog_sections = sections(_text(ROOT / "CHANGELOG.md"))
    old_release = next(section for name, _heading, section in changelog_sections if name == "0.6.2")
    assert "timeout-minutes: 30" in old_release


# ------------------------------------------------------------------- environment tables
def test_main_settings_table_lists_every_documented_switch():
    """E-17: UNIFI_TOOL_FAMILIES, DRY_RUN, AUDIT_LOG, AUDIT_LOG_FORMAT, FASTMCP_HOST/PORT."""
    text = _text(DOCS / "CONFIGURATION.md")
    start = text.index("| Variable | Required | Default | Description |")
    table = text[start : text.index("\n\n", start)]
    names = set(re.findall(r"^\| `([A-Z_]+)` \|", table, re.M))
    for name in (
        "UNIFI_TOOL_FAMILIES",
        "UNIFI_DRY_RUN",
        "UNIFI_AUDIT_LOG",
        "UNIFI_AUDIT_LOG_FORMAT",
        "FASTMCP_HOST",
        "FASTMCP_PORT",
    ):
        assert name in names, name
    for row in table.splitlines()[2:]:
        assert len(row.split("|")) >= 6 and row.split("|")[4].strip(), row  # a purpose each


# ---------------------------------------------------------------- unpinned install commands
def test_copy_paste_install_commands_are_pinned():
    """E-27: one policy: copy-paste commands pin the release they were written for."""
    bad = []
    for path in PUBLIC_MD:
        if path.name == "CHANGELOG.md":
            continue
        for no, line in enumerate(_text(path).splitlines(), 1):
            if re.search(r"--from\s+unifi-fabric-mcp-server(?![\w-])(?!==)", line):
                bad.append(f"{path.relative_to(ROOT)}:{no}: {line.strip()[:80]}")
            if re.search(r"(?:pip|pipx|uv tool) install\s+unifi-fabric-mcp-server(?!==)", line):
                bad.append(f"{path.relative_to(ROOT)}:{no}: {line.strip()[:80]}")
    assert not bad, "\n".join(bad)


# ------------------------------------------------------------------- statements vs the code
def test_source_checkout_instructions_install_first():
    """CX-3: ``python3 -m unifi_fabric.server`` fails in a clean checkout (ModuleNotFoundError)."""
    text = _text(README)
    assert "python3 -m unifi_fabric.server" not in text
    assert "python3 -m pip install -e ." in text


def test_compose_stdio_documents_the_spawn_command():
    """CX-4: a detached ``docker compose up`` of a stdio server exits 0 (no client on stdin)."""
    text = " ".join(_text(DOCS / "CONFIGURATION.md").split())
    assert "docker compose -f /absolute/path/to/compose.yml run --rm --no-deps -T" in text
    assert "Detached `docker compose up` does not provide the client's stdin/stdout" in text
    assert '"args": ["run", "--no-healthcheck", "--rm", "-i",' in _text(DOCS / "CONFIGURATION.md")


def test_json_validation_stays_local():
    """CX-5: no online validator for a value that holds API keys."""
    for path in PUBLIC_MD:
        text = _text(path)
        assert "jsonlint" not in text, path
    text = _text(README)
    assert 'json.loads(os.environ["UNIFI_API_KEYS"])' in text
    assert "Keep API keys out of online validators" in text


def test_recognition_paging_is_documented_as_it_behaves():
    """CX-7: no paging arguments drain all pages; ``page`` alone selects one page.

    Run against the fake upstream: no paging arguments return both pages with no
    continuation; ``page=1`` returns one page and ``nextPage`` 2.
    """

    import httpx
    import respx

    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings
    from unifi_fabric.tools._pagination import collect_links

    async def run() -> tuple[dict, dict]:
        with respx.mock(assert_all_called=False) as mock:

            def handler(request: httpx.Request) -> httpx.Response:
                page = int(request.url.params.get("page", "1"))
                links = {"next": "n"} if page < 2 else {}
                return httpx.Response(200, json={"groups": [{"id": f"g{page}"}], "links": links})

            mock.get(url__regex=r".*groups.*").mock(side_effect=handler)
            client = UniFiClient(Settings(api_key="sk-front-page-docs-test"))
            drained = await collect_links(client, "/v1/x/groups", "groups")
            single = await collect_links(client, "/v1/x/groups", "groups", page=1)
            return drained, single

    drained, single = asyncio.run(run())
    assert [i["id"] for i in drained["items"]] == ["g1", "g2"] and drained["nextPage"] is None
    assert [i["id"] for i in single["items"]] == ["g1"] and single["nextPage"] == 2
    text = " ".join(_text(DOCS / "TOOL-USAGE.md").split())
    assert "`_nextPage`" in text
    assert "recognition `page` / `page_size` -> nextPage" not in text
    assert "Recognition's `page_size` requests a total gathered across pages" in text


def test_tls_doc_does_not_claim_a_get_hangs():
    """CX-8: a sessionless GET /mcp returns an error response without doing an operation."""
    text = _text(DOCS / "TLS.md")
    assert "persistent SSE stream" not in text
    assert not re.search(r"\bhangs?\b", text, re.I)
    flat = _flat(DOCS / "TLS.md")
    assert "A sessionless GET returns HTTP 400 in stateful mode or 405 in stateless mode" in flat
    assert "does not demonstrate a successful MCP operation" in flat
    assert "The handshake probe must present a trusted client certificate." in flat
    # zsh supports <(...) process substitution too
    assert "supported by bash and zsh" in text and "dash/zsh" not in text


def test_oauth_scopes_are_documented_as_admission_not_roles():
    """CX-9: a scope named ``fabric:read`` does not disable write tools (``required_scopes``
    only gates admission; only the opt-in ``MCP_OAUTH_WRITE_SCOPE`` maps a scope to the
    write tools, and AUTH-OAUTH.md says so)."""
    sentence = "OAuth scopes control admission to the whole server."
    for path in (DOCS / "AUTH-OAUTH.md", DOCS / "CHATGPT.md", ROOT / ".github/SECURITY.md"):
        flat = " ".join(_text(path).split())
        assert sentence in flat, path
        assert "does not disable write tools" in flat, path
        assert "UNIFI_READ_ONLY=1" in flat, path
    flat = " ".join(_text(DOCS / "AUTH-OAUTH.md").split())
    assert "Every token the server accepts can call every tool, writes included." in flat
    assert "MCP_OAUTH_WRITE_SCOPE" in flat


def test_env_file_quoting_matches_docker_and_compose():
    """CX-LOW: verified with Docker 29 / Compose 5: ``--env-file`` keeps quotes literally;
    Compose ``env_file:`` strips them (``format: raw`` keeps them)."""
    flat = _flat(DOCS / "CONFIGURATION.md")
    assert "Docker CLI preserves them literally" in flat
    assert "`format: raw` preserves them" in flat
    assert "Do not put `export` in an env file" in flat
    for path in (README, DOCS / "CONFIGURATION.md"):
        assert "Docker reads the file literally" not in _text(path), path


def test_mtls_row_does_not_advertise_the_rejected_value():
    """CX-LOW: ``MCP_TLS_MODE=mtls`` with ``MCP_TLS_CERT_REQS=none`` fails startup."""
    from pydantic import ValidationError

    from unifi_fabric.config import MCPTransportSettings

    with pytest.raises(ValidationError, match="incompatible with MCP_TLS_CERT_REQS"):
        MCPTransportSettings(
            tls_mode="mtls",
            tls_certfile="/c.pem",
            tls_keyfile="/k.pem",
            tls_ca_certs="/ca.pem",
            tls_cert_reqs="none",
        )
    flat = " ".join(_text(DOCS / "AUTH-TLS.md").split())
    assert "`none` is rejected under `mtls`" in flat
    assert "Ignored under `https`" in flat


def test_redaction_reference_states_the_placement_exception_correctly():
    """CX-LOW, corrected: the placement projection withholds only when redaction is ON."""
    flat = " ".join(_text(DOCS / "CONFIGURATION.md").split())
    assert "ordinary tool responses" in flat
    assert "placement snapshot is a projection" in flat
    assert "with `UNIFI_REDACT_SECRETS` on" in flat and "`_withheld`" in flat


def test_uv_is_not_claimed_for_every_deployment():
    """CX-LOW: Docker deployments need Docker, not uv."""
    text = " ".join(_text(README).split())
    assert "Each needs [uv]" not in text
    assert "Docker deployments need Docker instead." in text
    assert "Local stdio setups use [uv](https://docs.astral.sh/uv/);" in text


# ------------------------------------------------------------------- community files
def test_community_health_files():
    """I-7: the live repo's community profile was at 75% for exactly these gaps."""
    coc = _text(ROOT / "CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in coc and "version 2.1" in coc
    assert PUBLIC_REPO.split("github.com/")[1] in coc or "SECURITY.md" in coc
    pr = _text(ROOT / ".github/PULL_REQUEST_TEMPLATE.md")
    for part in ("What changed", "How it was verified", "CHANGELOG"):
        assert part in pr, part
    config = _text(ROOT / ".github/ISSUE_TEMPLATE/config.yml")
    assert "blank_issues_enabled: false" in config
    assert f"{PUBLIC_REPO}/security/advisories/new" in config
    assert f"{PUBLIC_REPO}/discussions" in config
    sec = _text(ROOT / ".github/SECURITY.md")
    assert f"{PUBLIC_REPO}/security/advisories/new" in sec
    assert "whichever repository" not in sec


def test_conduct_contact_is_a_public_channel():
    coc = _text(ROOT / "CODE_OF_CONDUCT.md")
    assert "[INSERT CONTACT METHOD]" not in coc
    assert f"{PUBLIC_REPO}/security/advisories/new" in coc


def test_privacy_policy_covers_every_integration():
    """E-19: the Codex manifest links PRIVACY.md as its policy; it named only the Claude plugin."""
    first = " ".join(_text(ROOT / "PRIVACY.md").split("\n\n")[1].split())
    for part in (
        "container image",
        "Claude Code",
        "Claude Desktop",
        "Codex",
        "Antigravity",
        "Gemini CLI",
    ):
        assert part in first, part
    codex = json.loads(_text(ROOT / "plugins/codex/.codex-plugin/plugin.json"))
    assert codex["interface"]["privacyPolicyURL"].endswith("/PRIVACY.md")


def test_readme_no_longer_leads_with_changelog_content():
    """E-16: the removed ``include_secrets`` / ``include_gps`` parameters are CHANGELOG material."""
    head = "\n".join(_readme_lines()[:200])
    assert "have been removed" not in head
    assert "include_secrets" not in _text(README)


def test_troubleshooting_names_the_errors_users_see():
    """I-4: each entry quotes the message the code produces."""
    text = _text(README)
    block = text[text.index("## Troubleshooting") :]
    for part in (
        "HTTP 403",
        "refused: the server is in read-only mode",
        "ambiguous site",
        "cannot resolve '<name>' unambiguously",
        "Server starts but no tools appear",
    ):
        assert part in block, part
    from unifi_fabric import read_only

    assert "refused: the server is in read-only mode" in read_only.read_only_message("PUT")
