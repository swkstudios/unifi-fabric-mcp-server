"""User-facing docs stay current with the code (not a product gate).

Everything an operator copies from README.md, docs/*.md, server.json, the Dockerfile
examples, the client snippets in config/ and the Homebrew formula must name the
current release: version strings equal pyproject's version, prose tool counts equal
the tool registry, image references use the published image path, and documented
package / entry-point names equal pyproject's.

Historical mentions are allowed only when the line says so (an upgrade note, a
recorded live sweep, or an explicit ``docs-currency: historical`` marker). The
CHANGELOG is history and is never scanned.

Pin policy: version fields (pyproject, server.json, plugin/extension/manifest/formula
metadata) equal pyproject's version, the in-development release. User-facing install
pins (README/docs, plugin install args, client manifests, image tags) stay on the
latest PUBLISHED release in ``scripts/published-version.txt`` until the new version is
published; the release chain flips them at publication.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import importlib.util
import inspect
import json
import re
import tomllib
import urllib.parse
from pathlib import Path

import pytest

from scripts.gen_catalog_figures import PUBLISHED_VERSION
from unifi_fabric import server

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
VERSION = PYPROJECT["project"]["version"]

PACKAGE = PYPROJECT["project"]["name"]
ENTRY_POINTS = set(PYPROJECT["project"]["scripts"])

README = ROOT / "README.md"
PLUGIN_DIR = ROOT / "plugins" / "claude"
PLUGIN_MANIFEST = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
DOC_FILES = [
    README,
    *sorted((ROOT / "docs").glob("*.md")),
    ROOT / "CONTRIBUTING.md",
    ROOT / "AGENTS.md",
    ROOT / "PRIVACY.md",
    PLUGIN_DIR / "README.md",
    ROOT / "plugins" / "codex" / "README.md",
    ROOT / "plugins" / "antigravity" / "README.md",
    ROOT / "plugins" / "claude-desktop" / "README.md",
]
# Client integrations other than the Claude Code plugin: every manifest that pins the
# release or names a version (Codex plugin + repo marketplace, Antigravity plugin,
# Gemini CLI extension, Claude Desktop MCPB manifest).
CODEX_PLUGIN_DIR = ROOT / "plugins" / "codex"
CODEX_MANIFEST = CODEX_PLUGIN_DIR / ".codex-plugin" / "plugin.json"
CODEX_MCP = CODEX_PLUGIN_DIR / ".mcp.json"
CODEX_MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
ANTIGRAVITY_DIR = ROOT / "plugins" / "antigravity"
ANTIGRAVITY_MCP = ANTIGRAVITY_DIR / "mcp_config.json"
GEMINI_EXTENSION = ROOT / "gemini-extension.json"
MCPB_DIR = ROOT / "plugins" / "claude-desktop"
MCPB_MANIFEST = MCPB_DIR / "manifest.json"
INTEGRATION_MANIFESTS = [
    CODEX_MANIFEST,
    CODEX_MCP,
    CODEX_MARKETPLACE,
    ANTIGRAVITY_DIR / "plugin.json",
    ANTIGRAVITY_MCP,
    GEMINI_EXTENSION,
    MCPB_MANIFEST,
]
SNIPPET_FILES = [
    *DOC_FILES,
    ROOT / "server.json",
    PLUGIN_MANIFEST,
    *INTEGRATION_MANIFESTS,
    ROOT / "Dockerfile",
    *sorted((ROOT / "config").glob("*")),
]
FORMULA = ROOT / "packaging" / "homebrew" / "unifi-fabric-mcp-server.rb"

HISTORICAL = re.compile(
    r"docs-currency: historical|upgrading from|recorded (live )?sweep|sweep", re.I
)
IMAGE_RE = re.compile(
    r"ghcr\.io/(?P<org>[A-Za-z0-9_-]+)/(?P<name>[A-Za-z0-9_.-]+)"
    r"(?:(?P<sep>[:@])(?P<ref>[^\s\"'`)>\\]+))?"
)


def _tool_count() -> int:
    res = server.mcp.list_tools()
    if inspect.isawaitable(res):
        res = asyncio.run(res)
    return len(list(res))


@functools.cache
def _lz_TOOL_COUNT():
    return _tool_count()


def _lines(path: Path):
    yield from enumerate(path.read_text().splitlines(), 1)


@functools.cache
def _decoder():
    """The fixture gate's bounded URL / base64 / hex decoder (one implementation)."""
    path = ROOT / ".github" / "scripts" / "check_fixtures_sanitization.py"
    spec = importlib.util.spec_from_file_location("_docs_currency_decoder", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.decoded_views


def _views(line: str):
    """The line itself, then every text hidden under URL / base64 / hex layers of it.

    A version regex only sees raw text, so a pin inside a percent-encoded or base64
    deeplink payload (``%3D%3D0.7.0``, a Cursor ``config=`` blob) used to escape every
    check here. Each yield is (label suffix, text)."""
    yield "", line
    for layers, text in _decoder()(line):
        yield " (inside " + ">".join(layers) + " encoding)", text


def _upgrade_guide(path: Path) -> bool:
    """A ``MIGRATING-*`` guide records version transitions; scripts/prepare_release.py
    never renders it, so its version strings are history, not install pins."""
    return path.name.startswith("MIGRATING-")


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def test_files_exist():
    for path in (
        *DOC_FILES,
        ROOT / "server.json",
        ROOT / "Dockerfile",
        PLUGIN_MANIFEST,
        *INTEGRATION_MANIFESTS,
    ):
        assert path.is_file(), path


VERSION_RE = re.compile(r"(?<![\w.])0\.\d+\.\d+(?![\w.]*\d)")
TAG_RE = re.compile(r"`:(\d+\.\d+\.\d+)`|==(\d+\.\d+\.\d+)")
# "describes X.Y.Z source" names the source the document describes: always the current
# version (scripts/prepare_release.py renders it as a version field), never the published pin.
DESCRIBES_RE = re.compile(r"\bdescribes (0\.\d+\.\d+) source\b")


def _version_findings(path: Path, numbered) -> list[str]:
    """Stale 0.x.y project versions on ``numbered`` (lineno, line) pairs of ``path``,
    in the raw line and in every encoded layer of it."""
    bad = []
    for no, line in numbered:
        if (
            _upgrade_guide(path)
            or HISTORICAL.search(line)
            or "clientInfo" in line
            or (path.name == "Dockerfile" and "apt-get download" in line)
        ):
            continue
        for where, view in _views(line):
            described = {m.start(1) for m in DESCRIBES_RE.finditer(view)}
            for m in VERSION_RE.finditer(view):
                if m.group(0) != (
                    VERSION
                    if path == ROOT / "server.json"
                    or '"version":' in view
                    or "Tool counts at" in view
                    or m.start() in described
                    else PUBLISHED_VERSION
                ):
                    bad.append(f"{_rel(path)}:{no}: {m.group(0)} != {VERSION}{where}")
    return bad


def _tag_findings(path: Path, numbered) -> list[str]:
    """Backticked ``:X.Y.Z`` tags and ``==X.Y.Z`` pins that are not the published
    release, in the raw line and in every encoded layer of it."""
    bad = []
    for no, line in numbered:
        if _upgrade_guide(path) or HISTORICAL.search(line):
            continue
        for where, view in _views(line):
            for m in TAG_RE.finditer(view):
                found = m.group(1) or m.group(2)
                if found != PUBLISHED_VERSION:
                    bad.append(f"{_rel(path)}:{no}: {found} != {VERSION}{where}")
    return bad


def test_project_versions_in_docs_equal_pyproject():
    """Any 0.x.y project version in prose or snippets is the current one."""
    bad = [f for path in SNIPPET_FILES for f in _version_findings(path, _lines(path))]
    assert not bad, "stale version strings:\n" + "\n".join(bad)


def test_server_json_matches_pyproject():
    data = json.loads((ROOT / "server.json").read_text())
    assert data["version"] == VERSION
    for pkg in data["packages"]:
        if pkg["registryType"] == "oci":
            assert pkg["identifier"].rsplit(":", 1)[1] == VERSION
        else:
            assert pkg["version"] == VERSION


def test_image_references_use_published_path_and_current_version():
    bad = []
    seen = 0
    orgs: set[str] = set()
    for path in SNIPPET_FILES:
        for no, line in _lines(path):
            for m in IMAGE_RE.finditer(line):
                if m["name"] != PACKAGE:
                    continue
                seen += 1
                where = f"{_rel(path)}:{no}"
                if path.name != "server.json":  # the registry manifest names the public org
                    orgs.add(m["org"])
                if _upgrade_guide(path):
                    continue
                if m["sep"] == ":" and m["ref"] not in {
                    VERSION if path.name == "server.json" else PUBLISHED_VERSION,
                    "latest",
                }:
                    if not HISTORICAL.search(line):
                        bad.append(f"{where}: image tag {m['ref']} != {VERSION}")
    assert seen >= 5, "expected image references in the docs"
    assert len(orgs) == 1, (
        f"image references in the docs must use one published path, found {sorted(orgs)}"
    )
    assert not bad, "stale image references:\n" + "\n".join(bad)


def test_pinned_tag_mentions_equal_pyproject():
    """Backticked ``:X.Y.Z`` tag mentions and ``==X.Y.Z`` pins."""
    bad = [f for path in SNIPPET_FILES for f in _tag_findings(path, _lines(path))]
    assert not bad, "\n".join(bad)


def _stale_version() -> str:
    major, minor, patch = (int(x) for x in PUBLISHED_VERSION.split("."))
    return f"{major}.{minor}.{patch + 1}"


def _encoded_install_line(version: str) -> str:
    """A README-style line whose only pin sits inside two deeplink payloads: a
    percent-encoded VS Code config and a base64 Cursor config (built at runtime)."""
    config = json.dumps({"command": "uvx", "args": [f"{PACKAGE}=={version}"]})
    b64 = base64.b64encode(config.encode()).decode()
    return (
        f"[VS Code](vscode:mcp/install?{urllib.parse.quote(config)}) "
        f"[Cursor](cursor://anysphere.cursor-deeplink/mcp/install?config={b64})"
    )


@pytest.mark.parametrize("layer", ["url", "base64"])
def test_a_stale_pin_inside_an_encoding_is_caught(layer):
    """Negative control for the decode-aware scan: the raw line holds no visible pin,
    yet the stale one inside each encoded payload is reported, naming the layer."""
    line = _encoded_install_line(_stale_version())
    assert not TAG_RE.search(line), "the planted pin must not be visible raw"
    bad = _tag_findings(README, [(1, line)])
    assert any(f"(inside {layer} encoding)" in f for f in bad), bad


def test_the_current_pin_inside_an_encoding_passes():
    line = _encoded_install_line(PUBLISHED_VERSION)
    assert _tag_findings(README, [(1, line)]) == []
    assert _version_findings(README, [(1, line)]) == []


def test_encoded_benign_text_is_not_a_finding():
    prose = "Install the server, then restart the client to load the tools."
    hexed = prose.encode().hex()
    b64 = base64.b64encode(prose.encode()).decode()
    digest = hashlib.sha256(prose.encode()).hexdigest()
    line = f"{hexed} {b64} sha256:{digest} {urllib.parse.quote(prose)}"
    assert _tag_findings(README, [(1, line)]) == []
    assert _version_findings(README, [(1, line)]) == []


def test_homebrew_formula_url_names_current_release():
    text = FORMULA.read_text()
    tags = re.findall(r"refs/tags/v(\d+\.\d+\.\d+)\.tar\.gz", text)
    assert tags and set(tags) == {VERSION}, (tags, VERSION)


COUNT_RE = re.compile(r"(?<![\w.-])(\d{2,3}) (?:MCP )?tools\b|(\d{2,3}) tool names\b")


def _prose_count_findings(path: Path, numbered, count: int) -> tuple[int, list[str]]:
    """(raw claims seen, stale "N tools" claims) on ``numbered`` (lineno, line) pairs, in
    the raw line and in every URL / base64 / hex layer of it."""
    bad = []
    seen = 0
    for no, line in numbered:
        for where, view in _views(line):
            for m in COUNT_RE.finditer(view):
                n = int(m.group(1) or m.group(2))
                # "N tools remain and M are excluded" is the official-only subset
                # (UNIFI_EXCLUDE=unofficial,source:relay, also under UNIFI_WRITE_POLICY=deny),
                # rendered and checked against the running server by gen_catalog_figures.py.
                if re.match(r"\s+remain\s+and\s+\d+\s+are\s+excluded", view[m.end() :]):
                    continue
                # "this release's N tools" names the current catalog even on a line that
                # also cites a historical sweep, so the historical marker never exempts it.
                current = view[max(0, m.start() - 15) : m.start()].endswith("this release's ")
                if HISTORICAL.search(line) and n != count and not current:
                    continue
                seen += not where
                if n != count:
                    bad.append(f"{_rel(path)}:{no}: {n} != {count}{where}")
    return seen, bad


def test_prose_tool_counts_equal_registry():
    bad = []
    seen = 0
    # TOOLS.md is generated and checked by test_tools_reference_matches_registry; its
    # prose carries per-category counts, not the catalog size.
    for path in (p for p in DOC_FILES if p.name != "TOOLS.md"):
        if path.name == "MIGRATING-0.7.md":
            continue  # Historical release detail intentionally contains old counts.
        found, stale = _prose_count_findings(path, _lines(path), _lz_TOOL_COUNT())
        seen += found
        bad += stale
    assert seen >= 2, "expected tool-count claims in the docs"
    assert not bad, "stale tool counts:\n" + "\n".join(bad)


FAMILY_ROW_RE = re.compile(r"\| [A-Za-z][^|]* \| (\d+) ")
FAMILY_LISTED_RE = re.compile(r"\*\*(\d+)\*\* are in the product families")
FAMILY_REMAINING_RE = re.compile(r"The remaining (\d+) cover")
FAMILY_REGISTERED_RE = re.compile(r"\*\*(\d+) registered tools\*\*")


def _family_figures(text: str) -> tuple[list[int], int | None, int | None, int | None]:
    """(row counts, listed, remaining, registered) as ``text`` states them."""
    flat = " ".join(text.split())

    def one(pattern: re.Pattern[str]) -> int | None:
        m = pattern.search(flat)
        return int(m[1]) if m else None

    rows = [int(n) for n in FAMILY_ROW_RE.findall(text)]
    return rows, one(FAMILY_LISTED_RE), one(FAMILY_REMAINING_RE), one(FAMILY_REGISTERED_RE)


def _family_table_findings(block: str, count: int) -> list[str]:
    """Family-table figures that disagree with each other or with the registry: in the
    raw block (all four must be there) and in every encoded layer of a line of it (only
    the figures that layer states, each checked against what it can be checked against)."""
    rows, listed, remaining, registered = _family_figures(block)
    bad = []
    if not rows or None in (listed, remaining, registered):
        bad.append("family table not found")
    else:
        if sum(rows) != listed:
            bad.append(f"rows sum {sum(rows)} != listed {listed}")
        if not listed + remaining == registered == count:
            bad.append(
                f"listed {listed} + remaining {remaining}, registered {registered} != {count}"
            )
    for no, line in enumerate(block.splitlines(), 1):
        for where, view in _views(line):
            if not where:
                continue
            v_rows, v_listed, v_remaining, v_registered = _family_figures(view)
            if v_registered is not None and v_registered != count:
                bad.append(f"line {no}: registered {v_registered} != {count}{where}")
            if None not in (v_listed, v_remaining) and v_listed + v_remaining != count:
                bad.append(f"line {no}: listed + remaining != {count}{where}")
            if v_rows and v_listed is not None and sum(v_rows) != v_listed:
                bad.append(f"line {no}: rows sum {sum(v_rows)} != listed {v_listed}{where}")
    return bad


def test_readme_family_table_sums_to_registry():
    """The README family table plus the families it leaves out make up the registry."""
    text = README.read_text()
    start = text.index("<!-- BEGIN GENERATED: tool-families -->")
    block = text[start : text.index("<!-- END GENERATED -->", start)]
    assert _family_table_findings(block, _lz_TOOL_COUNT()) == []


def shape_totals() -> tuple[int, int, int]:
    """(shaped body parameters, free-form object parameters, bytes of all shapes).

    Bytes are the generated shapes as compact UTF-8 JSON, measured exactly as
    tests/test_catalog_size_budget.py holds them to their budget.
    """
    from unifi_fabric.generated_api_facts._tool_shapes_table import SHAPE_SOURCES, TOOL_SHAPES

    size = sum(
        len(json.dumps(shape, separators=(",", ":"), ensure_ascii=False).encode())
        for args in TOOL_SHAPES.values()
        for shape in args.values()
    )
    shaped = sum(1 for src in SHAPE_SOURCES.values() if src["classification"] == "shaped")
    free = sum(1 for src in SHAPE_SOURCES.values() if src["classification"] == "free-form")
    return shaped, free, size


SHAPE_CLAIM_RE = re.compile(
    r"the (\d+) pinned-spec request bodies [^(]*\(([\d,]+) bytes of compact JSON"
)


def test_catalog_body_shape_size_is_exact():
    """The catalog-size note (docs/CATALOG.md, and the README if it states one) is exact."""
    text = " ".join((ROOT / "docs" / "CATALOG.md").read_text().split())
    assert SHAPE_CLAIM_RE.findall(text), "docs/CATALOG.md states no body-shape size (vacuous)"
    text += " " + " ".join(README.read_text().split())
    shaped, _free, size = shape_totals()
    found = SHAPE_CLAIM_RE.findall(text)
    for count, size_text in found:
        assert (int(count), int(size_text.replace(",", ""))) == (shaped, size)
    # Not every tool carries an example call; the catalog-size prose must not say so.
    assert "and example call" not in text


REFERENCE_HEADING_RE = re.compile(r"^### ", re.M)
REFERENCE_CATEGORY_RE = re.compile(r"^- \[[^\]]+\]\(#[^)]+\) \((\d+)\)$", re.M)
ACCESS_ROW_RE = re.compile(r"^\| \[`(\w+)`\]\(#(\w+)\) \| `([\w-]+)` \| (read|write) \|$", re.M)
# An encoded layer is the whole line decoded, so a hidden entry does not start the line:
# the same three shapes, unanchored.
HIDDEN_HEADING_RE = re.compile(r"### `\w+`")
HIDDEN_CATEGORY_RE = re.compile(r"- \[[^\]]+\]\(#[^)]+\) \((\d+)\)")
HIDDEN_ACCESS_ROW_RE = re.compile(r"\| \[`(\w+)`\]\(#(\w+)\) \| `([\w-]+)` \| (read|write) \|")


def _tools_reference_findings(text: str, count: int) -> list[str]:
    """Reference headings and category counts that do not add up to the registry. An
    entry hidden under an encoding adds to both totals, so the registry cannot be met
    with one in the file."""
    headings = len(REFERENCE_HEADING_RE.findall(text))
    categories = [int(n) for n in REFERENCE_CATEGORY_RE.findall(text)]
    bad = []
    for no, line in enumerate(text.splitlines(), 1):
        for where, view in _views(line):
            if not where:
                continue
            hidden_headings = len(HIDDEN_HEADING_RE.findall(view))
            hidden_categories = [int(n) for n in HIDDEN_CATEGORY_RE.findall(view)]
            if hidden_headings or hidden_categories:
                bad.append(f"line {no}: a reference entry hidden{where}")
            headings += hidden_headings
            categories += hidden_categories
    if headings != count:
        bad.append(f"{headings} reference headings != {count}")
    if not categories or sum(categories) != count:
        bad.append(f"category counts sum {sum(categories)} != {count}")
    return bad


def test_tools_reference_matches_registry():
    text = (ROOT / "docs" / "TOOLS.md").read_text()
    assert _tools_reference_findings(text, _lz_TOOL_COUNT()) == []


def _access_index_findings(head: str, expected: list[tuple[str, str, str, str]]) -> list[str]:
    """Access-index rows that are not the registry's, in order, in the raw text; and any
    row hidden under an encoding (the index lists every tool once, in the clear)."""
    rows = ACCESS_ROW_RE.findall(head)
    bad = []
    if rows != expected:
        bad.append(f"{len(rows)} access rows differ from the {len(expected)} registry rows")
    for no, line in enumerate(head.splitlines(), 1):
        for where, view in _views(line):
            if where and HIDDEN_ACCESS_ROW_RE.search(view):
                known = any(row in expected for row in HIDDEN_ACCESS_ROW_RE.findall(view))
                bad.append(
                    f"line {no}: an access row hidden{where} "
                    f"({'a registry row listed again' if known else 'not a registry row'})"
                )
    return bad


def test_tools_reference_access_index_matches_registry():
    """The generated access index lists every tool once, with its family and access."""
    from scripts.gen_tools_doc import _runtime_tools
    from unifi_fabric.api_sources import selection_access
    from unifi_fabric.families import build_family_index

    text = (ROOT / "docs" / "TOOLS.md").read_text()
    head = text.split("\n## Filter expressions", 1)[0]
    assert "\n## Tool access index\n" in head  # at the top, before the reference
    tools = asyncio.run(_runtime_tools())
    families = build_family_index()
    expected = [
        (
            tool.name,
            tool.name.lower(),
            families[tool.name],
            selection_access(tool),
        )
        for tool in tools
    ]
    assert _access_index_findings(head, expected) == []
    assert len(expected) == _lz_TOOL_COUNT()
    headings = set(re.findall(r"^### `(\w+)`", text, re.M))
    assert {name for name, *_ in expected} == headings


def test_documented_package_and_entry_point_names():
    install_re = re.compile(r"(?:pip|pipx|uv tool) install\s+(?:-\S+\s+)*(?P<pkg>[A-Za-z][\w.-]*)")
    uvx_re = re.compile(r"uvx\s+--from\s+(?P<pkg>\S+)\s+(?P<ep>[\w.-]+)")
    json_uvx_re = re.compile(r'"--from",\s*"(?P<pkg>[^"]+)",\s*"(?P<ep>[^"]+)"')
    mcp_cmd_re = re.compile(r'"command":\s*"(?P<cmd>unifi[\w-]*)"')
    bad = []
    seen_pkg = seen_ep = 0
    for path in DOC_FILES:
        for no, line in _lines(path):
            for m in install_re.finditer(line):
                pkg = m["pkg"]
                if pkg in {"pip", "jq", "certifi"} or pkg.startswith("-"):
                    continue
                if pkg.startswith("unifi"):
                    seen_pkg += 1
                    if pkg != PACKAGE:
                        bad.append(f"{_rel(path)}:{no}: package {pkg} != {PACKAGE}")
            for rx in (uvx_re, json_uvx_re):
                for m in rx.finditer(line):
                    seen_pkg += 1
                    seen_ep += 1
                    # An exact pin (``pkg==X.Y.Z``) must name the current release.
                    pkg, _, pin = m["pkg"].partition("==")
                    if pkg != PACKAGE:
                        bad.append(f"{_rel(path)}:{no}: package {pkg} != {PACKAGE}")
                    if pin and pin != PUBLISHED_VERSION and not _upgrade_guide(path):
                        bad.append(f"{_rel(path)}:{no}: pin {pin} != {VERSION}")
                    if m["ep"] not in ENTRY_POINTS:
                        bad.append(f"{_rel(path)}:{no}: entry point {m['ep']}")
            for m in mcp_cmd_re.finditer(line):
                seen_ep += 1
                if m["cmd"] not in ENTRY_POINTS:
                    bad.append(f"{_rel(path)}:{no}: command {m['cmd']}")
    assert seen_pkg >= 3 and seen_ep >= 3
    assert not bad, "\n".join(bad)


@pytest.mark.parametrize("name", sorted(ENTRY_POINTS))
def test_entry_point_is_documented(name):
    assert name in README.read_text()


def test_claude_plugin_manifest_pins_current_release():
    """The Claude Code plugin launches the release it documents.

    ``plugins/claude`` runs ``uvx --from <package>==<version> <entry point>``. The
    manifest version and that exact pin both equal pyproject's version, so a release
    bump that misses the plugin fails here instead of shipping a plugin that launches
    the previous release.
    """
    data = json.loads(PLUGIN_MANIFEST.read_text())
    assert data["version"] == VERSION, (data["version"], VERSION)
    servers = data["mcpServers"]
    assert list(servers) == ["unifi-fabric"], list(servers)
    server_cfg = servers["unifi-fabric"]
    assert server_cfg["command"] == "uvx"
    assert server_cfg["args"] == ["--from", f"{PACKAGE}=={PUBLISHED_VERSION}", "unifi-fabric-mcp"]
    # The key comes only from the plugin's sensitive userConfig, never the user's env.
    assert server_cfg["env"]["UNIFI_API_KEY"] == "${user_config.unifi_api_key}"
    assert data["userConfig"]["unifi_api_key"]["sensitive"] is True
    assert server_cfg["env"]["UNIFI_WRITE_POLICY"] == "${user_config.write_policy}"
    assert data["userConfig"]["write_policy"]["default"] == "allow"


def test_claude_plugin_folder_is_self_contained():
    """Only the expected regular files ship in the plugin folder (no OS litter, links)."""
    skill_names = {
        "firewall-zone-policy-audit",
        "network-vlan-read-modify-write",
        "device-client-troubleshooting",
        "protect-camera-event-review",
        "wifi-radio-change",
        "site-health-report",
    }
    expected = {
        ".claude-plugin/plugin.json",
        ".claude-plugin/icon.png",
        "README.md",
        "LICENSE",
        *(f"skills/{name}/SKILL.md" for name in skill_names),
    }
    found = {p.relative_to(PLUGIN_DIR).as_posix() for p in PLUGIN_DIR.rglob("*") if p.is_file()}
    assert found == expected, sorted(found ^ expected)
    assert not [p for p in PLUGIN_DIR.rglob("*") if p.is_symlink()]


def _pinned_uvx(server_cfg: dict) -> None:
    """A stdio entry launches exactly ``uvx --from <package>==<version> <entry point>``."""
    assert server_cfg["command"] == "uvx", server_cfg
    assert server_cfg["args"] == [
        "--from",
        f"{PACKAGE}=={PUBLISHED_VERSION}",
        "unifi-fabric-mcp",
    ], server_cfg["args"]


def test_client_integrations_pin_current_release():
    """Codex, Antigravity, Gemini CLI and Claude Desktop manifests launch this release.

    Each manifest that carries a version equals pyproject's, and each server entry runs
    the exact ``==VERSION`` pin, so a release bump that misses one fails here.
    """
    codex = json.loads(CODEX_MANIFEST.read_text())
    assert codex["version"] == VERSION
    assert codex["mcpServers"] == "./.mcp.json"
    codex_mcp = json.loads(CODEX_MCP.read_text())["mcpServers"]
    assert list(codex_mcp) == ["unifi-fabric"]
    _pinned_uvx(codex_mcp["unifi-fabric"])

    market = json.loads(CODEX_MARKETPLACE.read_text())
    entries = {p["name"]: p for p in market["plugins"]}
    assert entries[codex["name"]]["source"] == {"source": "local", "path": "./plugins/codex"}

    ag_mcp = json.loads(ANTIGRAVITY_MCP.read_text())["mcpServers"]
    assert list(ag_mcp) == ["unifi-fabric"]
    _pinned_uvx(ag_mcp["unifi-fabric"])

    gemini = json.loads(GEMINI_EXTENSION.read_text())
    assert gemini["version"] == VERSION
    assert list(gemini["mcpServers"]) == ["unifi-fabric"]
    _pinned_uvx(gemini["mcpServers"]["unifi-fabric"])

    mcpb = json.loads(MCPB_MANIFEST.read_text())
    assert mcpb["version"] == VERSION
    _pinned_uvx(mcpb["server"]["mcp_config"])


def test_client_integrations_store_no_key():
    """No manifest carries a key value: the key comes from the user at run time.

    Codex forwards it from the environment (``env_vars``; its plugin config has no
    ``${VAR}`` expansion), Antigravity inherits the environment (its ``env`` values are
    literal), Gemini CLI and Claude Desktop prompt for it as a sensitive setting.
    """
    codex = json.loads(CODEX_MCP.read_text())["mcpServers"]["unifi-fabric"]
    assert "env" not in codex
    assert codex["env_vars"] == ["UNIFI_API_KEY", "UNIFI_WRITE_POLICY", "UNIFI_TOOL_MODE"]

    antigravity = json.loads(ANTIGRAVITY_MCP.read_text())["mcpServers"]["unifi-fabric"]
    assert "env" not in antigravity

    gemini = json.loads(GEMINI_EXTENSION.read_text())
    assert "env" not in gemini["mcpServers"]["unifi-fabric"]
    settings = {s["envVar"]: s for s in gemini["settings"]}
    assert settings["UNIFI_API_KEY"]["sensitive"] is True

    mcpb = json.loads(MCPB_MANIFEST.read_text())
    env = mcpb["server"]["mcp_config"]["env"]
    assert env["UNIFI_API_KEY"] == "${user_config.unifi_api_key}"
    assert env["UNIFI_WRITE_POLICY"] == "${user_config.write_policy}"
    assert mcpb["user_config"]["unifi_api_key"]["sensitive"] is True
    assert mcpb["user_config"]["write_policy"]["default"] == "allow"


def test_client_integrations_default_to_discovery_with_full_opt_out():
    """Every manifest leaves discovery as the default and lets the user choose full.

    Discovery is the server default (``Settings.tool_mode``). Manifests that prompt for
    settings expose a non-secret tool-mode option defaulting to ``discovery``; manifests
    that inherit or forward the environment never pin a literal value, so an exported
    ``UNIFI_TOOL_MODE=full`` still takes effect.
    """
    from unifi_fabric.config import Settings

    assert Settings.model_fields["tool_mode"].default == "discovery"

    for path, env, options in (
        (PLUGIN_MANIFEST, ("mcpServers", "unifi-fabric", "env"), "userConfig"),
        (MCPB_MANIFEST, ("server", "mcp_config", "env"), "user_config"),
    ):
        data = json.loads(path.read_text())
        server_env = data
        for key in env:
            server_env = server_env[key]
        assert server_env["UNIFI_TOOL_MODE"] == "${user_config.tool_mode}", path
        option = data[options]["tool_mode"]
        assert option["type"] == "string" and option["default"] == "discovery", path
        assert not option.get("sensitive") and not option.get("required"), path
        assert "full" in option["description"], path

    codex = json.loads(CODEX_MCP.read_text())["mcpServers"]["unifi-fabric"]
    assert "UNIFI_TOOL_MODE" in codex["env_vars"] and "env" not in codex
    antigravity = json.loads(ANTIGRAVITY_MCP.read_text())["mcpServers"]["unifi-fabric"]
    assert "env" not in antigravity

    gemini = json.loads(GEMINI_EXTENSION.read_text())
    setting = {s["envVar"]: s for s in gemini["settings"]}["UNIFI_TOOL_MODE"]
    assert setting["sensitive"] is False and "full" in setting["description"]

    registry = json.loads((ROOT / "server.json").read_text())
    variables = [
        v
        for package in registry["packages"]
        for v in package.get("environmentVariables", [])
        if v["name"] == "UNIFI_TOOL_MODE"
    ]
    assert variables, "server.json declares no UNIFI_TOOL_MODE"
    for variable in variables:
        assert variable["default"] == "discovery"
        assert variable["choices"] == ["discovery", "full", "codemode"]
        assert variable["isRequired"] is False


@pytest.mark.parametrize(
    ("folder", "expected"),
    [
        (
            CODEX_PLUGIN_DIR,
            {
                ".codex-plugin/plugin.json",
                ".mcp.json",
                "README.md",
                "assets/composer-icon.png",
                "assets/logo.png",
            },
        ),
        (ANTIGRAVITY_DIR, {"plugin.json", "mcp_config.json", "README.md"}),
        (
            MCPB_DIR,
            {
                "README.md",
                "icon-128.png",
                "icon-16.png",
                "icon-256.png",
                "icon-32.png",
                "icon-64.png",
                "icon-light-128.png",
                "icon-light-16.png",
                "icon-light-256.png",
                "icon-light-32.png",
                "icon-light-64.png",
                "icon-light.png",
                "icon.png",
                "manifest.json",
            },
        ),
        (ROOT / ".agents", {"plugins/marketplace.json"}),
    ],
    ids=["codex", "antigravity", "claude-desktop", "agents"],
)
def test_client_integration_folders_are_self_contained(folder, expected):
    """Only the expected regular files ship in each integration folder."""
    found = {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()}
    assert found == expected, sorted(found ^ expected)
    assert not [p for p in folder.rglob("*") if p.is_symlink()]


def test_migration_guide_is_in_the_documentation_corpus():
    guide = ROOT / "docs" / "MIGRATING-0.7.md"
    assert guide in DOC_FILES
    assert "# Migrating to 0.7.0" in guide.read_text()


#: The 0.7.1 settings migration kit. 0.7.2 removes it from the tree; the v0.7.1 tag keeps
#: serving it, and the startup refusal for a retired setting links it there.
_MIGRATION_KIT = (
    "docs/MIGRATING-0.7.1.md",
    "tools/migrate-0.7.1-env.py",
    "tests/fixtures/upgrade-0.7.1",
    "tests/test_upgrade_0_7_1.py",
)
_KIT_TAG = "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/"
_KIT_GUIDE_URL = _KIT_TAG + "docs/MIGRATING-0.7.1.md"
_KIT_COMMAND = (
    "uv run https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/v0.7.1/"
    "tools/migrate-0.7.1-env.py <config file>"
)
_RELATIVE_KIT_LINK = re.compile(r"\]\((?!https?://)[^)]*MIGRATING-0\.7\.1\.md[^)]*\)")


def test_071_migration_kit_is_not_in_the_tree():
    """0.7.2 deletes the 0.7.1 migration kit; the v0.7.1 tag keeps the old links alive."""
    assert [rel for rel in _MIGRATION_KIT if (ROOT / rel).exists()] == []


def test_startup_refusal_points_at_the_071_kit_on_its_tag():
    """A 0.7.0 setting still refuses startup with the guide and the migrator, on the tag."""
    from unifi_fabric import policy

    assert policy.MIGRATION_URL == _KIT_GUIDE_URL
    assert policy.MIGRATION_COMMAND == _KIT_COMMAND
    retired = "UNIFI_" + "EXAMPLE_FROM_070"
    with pytest.raises(policy.StartupRefusal) as info:
        policy.check_retired_settings({retired: "1"}, ())
    assert info.value.token == f"startup:retired:{retired}"
    assert f"Migrate: {_KIT_GUIDE_URL} (one command: {_KIT_COMMAND})" in info.value.message


def test_docs_link_the_071_migration_guide_on_its_tag():
    """No document links the removed guide by a relative path; the upgrade notes use the tag."""
    docs = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    relative = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in docs
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if _RELATIVE_KIT_LINK.search(line)
    ]
    assert relative == []
    for rel in ("README.md", "docs/CLIENT-SETUP.md", "docs/MIGRATING-0.7.md"):
        assert f"]({_KIT_GUIDE_URL})" in (ROOT / rel).read_text(), rel


def test_readme_links_the_072_migration_guide_for_a_071_upgrader():
    """README gives a 0.7.1 upgrader a path to the 0.7.2 guide (note and table)."""
    text = (ROOT / "README.md").read_text()
    assert (ROOT / "docs" / "MIGRATING-0.7.2.md").is_file()
    assert text.count("](docs/MIGRATING-0.7.2.md)") >= 2


def _gen_tools_doc():
    script = ROOT / "scripts" / "gen_tools_doc.py"
    spec = importlib.util.spec_from_file_location("gen_tools_doc", script)
    gen = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(gen)
    return gen


def _release_count_findings(path: Path, numbered, count: int) -> list[str]:
    """Release-count phrases ("this release's N tools") that are not ``count``, in the raw
    line and in every encoded layer of it."""
    pattern = _gen_tools_doc().RELEASE_COUNT_RE
    return [
        f"{_rel(path)}:{no}: {m.group(2)} != {count}{where}"
        for no, line in numbered
        for where, view in _views(line)
        for m in pattern.finditer(view)
        if int(m.group(2)) != count
    ]


def test_release_count_phrases_are_generated_from_the_registry():
    """gen_tools_doc owns every "this release's N tools" phrase (docs/COVERAGE.md)."""
    gen = _gen_tools_doc()
    stale = gen.release_count_drift(_lz_TOOL_COUNT())
    assert stale == [], f"run python3 scripts/gen_tools_doc.py: {stale}"
    hidden = [
        finding
        for path in gen.RELEASE_COUNT_FILES
        for finding in _release_count_findings(path, _lines(path), _lz_TOOL_COUNT())
    ]
    assert hidden == [], f"run python3 scripts/gen_tools_doc.py: {hidden}"
    assert any("this release's" in p.read_text() for p in gen.RELEASE_COUNT_FILES)


def test_install_pins_equal_published_version_and_version_fields_equal_pyproject():
    """Install pins == published-version.txt; version fields == pyproject version."""
    published = (ROOT / "scripts" / "published-version.txt").read_text().strip()
    assert published == PUBLISHED_VERSION

    pin = re.compile(re.escape(PACKAGE) + r"==(\d+\.\d+\.\d+)")
    for path in (PLUGIN_MANIFEST, CODEX_MCP, ANTIGRAVITY_MCP, GEMINI_EXTENSION, MCPB_MANIFEST):
        found = pin.findall(path.read_text())
        assert found, f"{path.name}: no install pin"
        assert set(found) == {published}, (path.name, found, published)

    for path in (PLUGIN_MANIFEST, CODEX_MANIFEST, GEMINI_EXTENSION, MCPB_MANIFEST):
        assert json.loads(path.read_text())["version"] == VERSION, path.name
    registry = json.loads((ROOT / "server.json").read_text())
    assert registry["version"] == VERSION
    for package in registry["packages"]:
        assert package.get("version", package["identifier"].rpartition(":")[2]) == VERSION


# --- negative controls: one per literal kind, each planted under every encoding layer ----------
#
# A literal scan that reads raw text only is blind to a stale figure inside a percent-encoded,
# base64 or hex payload. Each control plants the stale literal where the raw line shows
# nothing the check's own pattern matches, and requires the finding to name the layer.

LAYERS = ["url", "base64", "hex"]


def _hide(text: str, layer: str) -> str:
    """``text`` as one encoded payload inside a deeplink-shaped line (built at runtime)."""
    if layer == "url":
        return f"[VS Code](vscode:mcp/install?{urllib.parse.quote(text, safe='')})"
    if layer == "base64":
        return f"[Cursor](cursor://anysphere.cursor-deeplink/mcp/install?config={base64.b64encode(text.encode()).decode()})"
    return f"payload {text.encode().hex()}"


def _inside(layer: str) -> str:
    return f"(inside {layer} encoding)"


@pytest.mark.parametrize("layer", LAYERS)
def test_a_stale_prose_tool_count_inside_an_encoding_is_caught(layer):
    count = _lz_TOOL_COUNT()
    stale = _hide(f"The server registers {count + 1} tools.", layer)
    assert not COUNT_RE.search(stale), "the planted count must not be visible raw"
    _seen, bad = _prose_count_findings(README, [(1, stale)], count)
    assert any(_inside(layer) in f for f in bad), bad
    current = _hide(f"The server registers {count} tools.", layer)
    assert _prose_count_findings(README, [(1, current)], count)[1] == []


@pytest.mark.parametrize("layer", LAYERS)
def test_a_stale_family_table_figure_inside_an_encoding_is_caught(layer):
    count = _lz_TOOL_COUNT()
    stale = _hide(f"**{count + 1} registered tools**", layer)
    assert not FAMILY_REGISTERED_RE.search(stale), "the planted figure must not be visible raw"
    bad = _family_table_findings(stale, count)
    assert any(_inside(layer) in f for f in bad), bad
    current = _hide(f"**{count} registered tools**", layer)
    assert not any("inside" in f for f in _family_table_findings(current, count))


@pytest.mark.parametrize("layer", LAYERS)
def test_a_stale_release_count_phrase_inside_an_encoding_is_caught(layer):
    count = _lz_TOOL_COUNT()
    pattern = _gen_tools_doc().RELEASE_COUNT_RE
    stale = _hide(f"this release's {count + 1} tools", layer)
    assert not pattern.search(stale), "the planted phrase must not be visible raw"
    bad = _release_count_findings(README, [(1, stale)], count)
    assert any(_inside(layer) in f for f in bad), bad
    current = _hide(f"this release's {count} tools", layer)
    assert _release_count_findings(README, [(1, current)], count) == []


@pytest.mark.parametrize("layer", LAYERS)
def test_a_reference_entry_hidden_inside_an_encoding_is_caught(layer):
    count = 3
    clear = "\n".join([*(f"### `tool_{i}`" for i in range(count)), f"- [All](#all) ({count})"])
    assert _tools_reference_findings(clear, count) == []
    hidden = _hide("### `tool_extra`\n- [Extra](#extra) (1)", layer)
    assert not REFERENCE_HEADING_RE.search(hidden), "the planted entry must not be visible raw"
    bad = _tools_reference_findings(clear + "\n" + hidden, count)
    assert any(_inside(layer) in f for f in bad), bad


@pytest.mark.parametrize("layer", LAYERS)
def test_an_access_row_hidden_inside_an_encoding_is_caught(layer):
    expected = [("get_thing", "get_thing", "network", "read")]
    clear = "| [`get_thing`](#get_thing) | `network` | read |"
    assert _access_index_findings(clear, expected) == []
    stale = _hide("| [`get_thing`](#get_thing) | `network` | write |", layer)
    assert not ACCESS_ROW_RE.search(stale), "the planted row must not be visible raw"
    bad = _access_index_findings(clear + "\n" + stale, expected)
    assert any(_inside(layer) in f and "not a registry row" in f for f in bad), bad
