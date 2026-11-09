"""Resolution result compatibility and error contracts are documented for 0.7.0."""

from pathlib import Path


def test_resolution_changes_are_documented():
    text = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text()
    release = text.split("## [0.7.0]", 1)[1].split("\n## [", 1)[0]
    guide = (Path(__file__).resolve().parents[1] / "docs" / "MIGRATING-0.7.md").read_text()
    fixed = release.split("### Fixed", 1)[1].split("\n### ", 1)[0]
    breaking = guide.split("## 0.7.0 behaviour changes", 1)[1].split("\n## ", 1)[0]
    changed = breaking
    assert "_incomplete" in changed and "_incompleteReason" in changed
    assert "{result, incomplete, incompleteReason}" in changed
    assert "Device and client resolvers reject an ambiguous MAC or id" in fixed
    assert "addresses the record by its native `_id`" in fixed
    assert "Breaking (resolution provenance): `_incompleteReason`" in breaking
