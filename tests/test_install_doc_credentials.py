"""Install documentation keeps credentials off command lines and links the pinned bundle."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_doc_links as links  # noqa: E402
import extract_install_cases as extraction  # noqa: E402
import gen_catalog_figures as figures  # noqa: E402
from markdown_blocks import fenced_blocks  # noqa: E402

#: Credentials that must never appear as a value on a documented command line: any local
#: user can read a process's arguments, and an argument lands in shell history.
CREDENTIALS = frozenset({"UNIFI_API_KEY", "UNIFI_API_KEYS", "MCP_BEARER_TOKEN"})
PUBLIC = "https://github.com/swkstudios/unifi-fabric-mcp-server"


def _docker_argvs(language: str, body: str):
    """Yield the argument list of every ``docker run`` in a fenced example."""
    if language == "json":
        try:
            config = json.loads(body)
        except ValueError:
            return
        servers = config.get("mcpServers", {}) if isinstance(config, dict) else {}
        for server in servers.values():
            if isinstance(server, dict) and server.get("command") == "docker":
                yield ["docker", *server.get("args", [])]
        return
    for line in body.replace("\\\n", " ").splitlines():
        start = line.find("docker run ")
        if start != -1:
            yield shlex.split(line[start:], comments=True)


def _credential_values(argv: list[str]) -> list[str]:
    found = []
    for index, value in enumerate(argv):
        if value in {"-e", "--env"} and index + 1 < len(argv):
            assignment = argv[index + 1]
        elif value.startswith("--env="):
            assignment = value.removeprefix("--env=")
        else:
            continue
        name, sep, _ = assignment.partition("=")
        if sep and name in CREDENTIALS:
            found.append(name)
    return found


def offenders(root: Path) -> list[str]:
    out = []
    for path in extraction.public_documents(root):
        text = path.read_text(encoding="utf-8")
        for offset, language, body in fenced_blocks(text):
            for argv in _docker_argvs(language, body):
                for name in _credential_values(argv):
                    line = text[:offset].count("\n") + 1
                    out.append(f"{path.relative_to(root)}:{line}: docker run -e {name}=<value>")
    return out


def test_no_public_docker_example_passes_a_credential_value():
    assert offenders(ROOT) == []


@pytest.mark.parametrize(
    "body, flagged",
    [
        ('```bash\ndocker run -e UNIFI_API_KEY="your-api-key-here" -p 3000:3000 image\n```\n', 1),
        ("```bash\ndocker run \\\n  -e MCP_BEARER_TOKEN=abc \\\n  image\n```\n", 1),
        (
            '```json\n{"mcpServers":{"x":{"command":"docker","args":'
            '["run","-e","UNIFI_API_KEY=k","image"]}}}\n```\n',
            1,
        ),
        ("```bash\ndocker run -e UNIFI_API_KEY -e MCP_BEARER_TOKEN -p 3000:3000 image\n```\n", 0),
        ("```bash\ndocker run -e UNIFI_WRITE_POLICY=deny -e UNIFI_API_KEY image\n```\n", 0),
    ],
)
def test_guard_flags_exactly_the_credential_values(tmp_path, body, flagged):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(body)
    assert len(offenders(tmp_path)) == flagged


def _bundle(version: str) -> str:
    return f"{PUBLIC}/releases/download/v{version}/unifi-fabric-{version}.mcpb"


def test_claude_desktop_install_links_download_the_pinned_bundle():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    published = (ROOT / "scripts" / "published-version.txt").read_text().strip()
    badge = re.search(r'<a href="([^"]+)"><img [^>]*alt="Install in Claude Desktop"', readme)
    assert badge is not None
    assert badge[1] == _bundle(published)
    assert f"[download the Claude Desktop extension (.mcpb)]({_bundle(published)})" in readme
    assert "releases/latest" not in readme


def test_bundle_link_follows_the_version_renderer():
    assert figures.render_install_versions(_bundle("0.7.0"), "9.8.7") == _bundle("9.8.7")


@pytest.fixture
def bundle_project(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    manifest = tmp_path / "plugins" / "claude-desktop" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"version": "1.2.3"}')
    return tmp_path


def test_current_bundle_link_is_checked_against_the_manifest(bundle_project):
    result = links.current_release_bundle(_bundle("1.2.3"), bundle_project, "1.2.3")
    assert result is not None and result["ok"] is True


@pytest.mark.parametrize("declared", ['{"version": "1.2.2"}', "{broken", None])
def test_bundle_link_without_a_matching_manifest_fails(bundle_project, declared):
    manifest = bundle_project / "plugins" / "claude-desktop" / "manifest.json"
    if declared is None:
        manifest.unlink()
    else:
        manifest.write_text(declared)
    result = links.current_release_bundle(_bundle("1.2.3"), bundle_project, "1.2.3")
    assert result is not None and result["ok"] is False and result["status"] == 404


@pytest.mark.parametrize(
    "url",
    [
        _bundle("1.2.2"),
        f"{PUBLIC}/releases/download/v1.2.3/other-1.2.3.mcpb",
        _bundle("1.2.3") + "?raw=1",
        _bundle("1.2.3").replace("swkstudios", "someone-else"),
    ],
)
def test_other_release_downloads_keep_the_http_probe(bundle_project, url):
    assert links.current_release_bundle(url, bundle_project, "1.2.3") is None
