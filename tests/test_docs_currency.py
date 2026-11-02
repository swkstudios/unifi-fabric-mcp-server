"""User-facing docs stay current with the code (not a product gate).

Everything an operator copies from README.md, docs/*.md, server.json, the Dockerfile
examples, the client snippets in config/ and the Homebrew formula must name the
current release: version strings equal pyproject's version, prose tool counts equal
the tool registry, image references use the published image path, and documented
package / entry-point names equal pyproject's.

Historical mentions are allowed only when the line says so (an upgrade note, a
recorded live sweep, or an explicit ``docs-currency: historical`` marker). The
CHANGELOG is history and is never scanned.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import re
import tomllib
from pathlib import Path

import pytest

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


def test_project_versions_in_docs_equal_pyproject():
    """Any 0.x.y project version in prose or snippets is the current one."""
    version_re = re.compile(r"(?<![\w.])0\.\d+\.\d+(?![\w.]*\d)")
    bad = []
    for path in SNIPPET_FILES:
        for no, line in _lines(path):
            if path.name == "MIGRATING-0.7.md" or HISTORICAL.search(line) or "clientInfo" in line:
                continue
            for m in version_re.finditer(line):
                if m.group(0) != VERSION:
                    bad.append(f"{_rel(path)}:{no}: {m.group(0)} != {VERSION}")
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
                if m["sep"] == ":" and m["ref"] not in {VERSION, "latest"}:
                    if not HISTORICAL.search(line):
                        bad.append(f"{where}: image tag {m['ref']} != {VERSION}")
    assert seen >= 5, "expected image references in the docs"
    assert len(orgs) == 1, (
        f"image references in the docs must use one published path, found {sorted(orgs)}"
    )
    assert not bad, "stale image references:\n" + "\n".join(bad)


def test_pinned_tag_mentions_equal_pyproject():
    """Backticked ``:X.Y.Z`` tag mentions and ``==X.Y.Z`` pins."""
    tag_re = re.compile(r"`:(\d+\.\d+\.\d+)`|==(\d+\.\d+\.\d+)")
    bad = []
    for path in SNIPPET_FILES:
        for no, line in _lines(path):
            if HISTORICAL.search(line):
                continue
            for m in tag_re.finditer(line):
                found = m.group(1) or m.group(2)
                if found != VERSION:
                    bad.append(f"{_rel(path)}:{no}: {found} != {VERSION}")
    assert not bad, "\n".join(bad)


def test_homebrew_formula_url_names_current_release():
    text = FORMULA.read_text()
    tags = re.findall(r"refs/tags/v(\d+\.\d+\.\d+)\.tar\.gz", text)
    assert tags and set(tags) == {VERSION}, (tags, VERSION)


def test_prose_tool_counts_equal_registry():
    count_re = re.compile(r"(?<![\w.-])(\d{2,3}) (?:MCP )?tools\b|(\d{2,3}) tool names\b")
    bad = []
    seen = 0
    # TOOLS.md is generated and checked by test_tools_reference_matches_registry; its
    # prose carries per-category counts, not the catalog size.
    for path in (p for p in DOC_FILES if p.name != "TOOLS.md"):
        if path.name == "MIGRATING-0.7.md":
            continue  # Historical release detail intentionally contains old counts.
        for no, line in _lines(path):
            for m in count_re.finditer(line):
                n = int(m.group(1) or m.group(2))
                # "this release's N tools" names the current catalog even on a line that
                # also cites a historical sweep, so the historical marker never exempts it.
                current = line[max(0, m.start() - 15) : m.start()].endswith("this release's ")
                if HISTORICAL.search(line) and n != _lz_TOOL_COUNT() and not current:
                    continue
                seen += 1
                if n != _lz_TOOL_COUNT():
                    bad.append(f"{_rel(path)}:{no}: {n} != {_lz_TOOL_COUNT()}")
    assert seen >= 2, "expected tool-count claims in the docs"
    assert not bad, "stale tool counts:\n" + "\n".join(bad)


def test_readme_domain_table_sums_to_registry():
    text = README.read_text()
    start = text.index("| Domain | Domain tools available | Purpose |")
    block = text[start : text.index("\n\n", start)]
    counts = [int(m) for m in re.findall(r"^\| \*\*[^|]+\*\* \| (\d+) \|", block, re.M)]
    assert counts, "domain table not found"
    assert sum(counts) == _lz_TOOL_COUNT(), (sum(counts), _lz_TOOL_COUNT())


def shape_totals() -> tuple[int, int, int]:
    """(shaped body parameters, free-form object parameters, bytes of all shapes).

    Bytes are the generated shapes as compact UTF-8 JSON, measured exactly as
    tests/test_catalog_size_budget.py holds them to their budget.
    """
    from unifi_fabric._tool_shapes_table import SHAPE_SOURCES, TOOL_SHAPES

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


def test_readme_body_shape_size_is_exact():
    text = " ".join(README.read_text().split())
    shaped, _free, size = shape_totals()
    found = SHAPE_CLAIM_RE.findall(text)
    assert found, "README states no body-shape size (vacuous)"
    for count, size_text in found:
        assert (int(count), int(size_text.replace(",", ""))) == (shaped, size)
    # Not every tool carries an example call; the catalog-size prose must not say so.
    assert "and example call" not in text


def test_tools_reference_matches_registry():
    text = (ROOT / "docs" / "TOOLS.md").read_text()
    assert len(re.findall(r"^### ", text, re.M)) == _lz_TOOL_COUNT()
    cats = [int(n) for n in re.findall(r"^- \[[^\]]+\]\(#[^)]+\) \((\d+)\)$", text, re.M)]
    assert cats and sum(cats) == _lz_TOOL_COUNT(), (sum(cats), _lz_TOOL_COUNT())


def test_tools_reference_access_index_matches_registry():
    """The generated access index lists every tool once, with its family and access."""
    from scripts.gen_tools_doc import _runtime_tools
    from unifi_fabric.api_sources import selection_access
    from unifi_fabric.families import build_family_index

    text = (ROOT / "docs" / "TOOLS.md").read_text()
    head = text.split("\n## Filter expressions", 1)[0]
    assert "\n## Tool access index\n" in head  # at the top, before the reference
    rows = re.findall(r"^\| \[`(\w+)`\]\(#(\w+)\) \| `([\w-]+)` \| (read|write) \|$", head, re.M)
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
    assert rows == expected
    assert len(rows) == _lz_TOOL_COUNT()
    headings = set(re.findall(r"^### `(\w+)`", text, re.M))
    assert {name for name, *_ in rows} == headings


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
                    if pin and pin != VERSION:
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
    assert server_cfg["args"] == ["--from", f"{PACKAGE}=={VERSION}", "unifi-fabric-mcp"]
    # The key comes only from the plugin's sensitive userConfig, never the user's env.
    assert server_cfg["env"]["UNIFI_API_KEY"] == "${user_config.unifi_api_key}"
    assert data["userConfig"]["unifi_api_key"]["sensitive"] is True
    assert server_cfg["env"]["UNIFI_READ_ONLY"] == "${user_config.read_only}"
    assert data["userConfig"]["read_only"]["default"] is False


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
    assert server_cfg["args"] == ["--from", f"{PACKAGE}=={VERSION}", "unifi-fabric-mcp"], (
        server_cfg["args"]
    )


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
    assert codex["env_vars"] == ["UNIFI_API_KEY", "UNIFI_READ_ONLY", "UNIFI_TOOL_MODE"]

    antigravity = json.loads(ANTIGRAVITY_MCP.read_text())["mcpServers"]["unifi-fabric"]
    assert "env" not in antigravity

    gemini = json.loads(GEMINI_EXTENSION.read_text())
    assert "env" not in gemini["mcpServers"]["unifi-fabric"]
    settings = {s["envVar"]: s for s in gemini["settings"]}
    assert settings["UNIFI_API_KEY"]["sensitive"] is True

    mcpb = json.loads(MCPB_MANIFEST.read_text())
    env = mcpb["server"]["mcp_config"]["env"]
    assert env["UNIFI_API_KEY"] == "${user_config.unifi_api_key}"
    assert env["UNIFI_READ_ONLY"] == "${user_config.read_only}"
    assert mcpb["user_config"]["unifi_api_key"]["sensitive"] is True
    assert mcpb["user_config"]["read_only"]["default"] is False


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
        assert variable["choices"] == ["discovery", "full"]
        assert variable["isRequired"] is False


@pytest.mark.parametrize(
    ("folder", "expected"),
    [
        (CODEX_PLUGIN_DIR, {".codex-plugin/plugin.json", ".mcp.json", "README.md"}),
        (ANTIGRAVITY_DIR, {"plugin.json", "mcp_config.json", "README.md"}),
        (MCPB_DIR, {"manifest.json", "README.md"}),
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


def test_release_count_phrases_are_generated_from_the_registry():
    """gen_tools_doc owns every "this release's N tools" phrase (docs/COVERAGE.md)."""
    import importlib.util

    script = ROOT / "scripts" / "gen_tools_doc.py"
    spec = importlib.util.spec_from_file_location("gen_tools_doc", script)
    gen = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(gen)
    stale = gen.release_count_drift(_lz_TOOL_COUNT())
    assert stale == [], f"run python3 scripts/gen_tools_doc.py: {stale}"
    assert any("this release's" in p.read_text() for p in gen.RELEASE_COUNT_FILES)
