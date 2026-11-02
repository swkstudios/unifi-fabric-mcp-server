"""Registry discovery is described alongside the shipped Registry metadata."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_registry_release_note_names_discovery_metadata():
    release = (ROOT / "CHANGELOG.md").read_text().split("## [0.7.0]", 1)[1].split("## [", 1)[0]
    fragments = "\n".join(path.read_text() for path in (ROOT / "changelog.d").glob("*.added.md"))
    note = next(
        (line for line in (release + "\n" + fragments).splitlines() if "MCP Registry" in line), ""
    )
    assert "server.json" in note and "mcp-name" in note
    assert (ROOT / "server.json").is_file()
    assert "mcp-name:" in (ROOT / "README.md").read_text()
