"""Resolution result compatibility and error contracts are documented for 0.7.0."""

from pathlib import Path


def test_resolution_changes_are_documented():
    text = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text()
    release = text.split("## [0.7.0]", 1)[1].split("\n## [", 1)[0]
    guide = (Path(__file__).resolve().parents[1] / "docs" / "MIGRATING-0.7.md").read_text()
    fixed = release.split("### Fixed", 1)[1].split("\n### ", 1)[0]
    breaking = guide
    changed = guide
    assert "_incomplete" in changed and "_incompleteReason" in changed
    assert "{result, incomplete, incompleteReason}" in changed
    assert "ambiguous" in fixed and "MAC" in fixed and "id" in fixed
    assert "native" in fixed and "`_id`" in fixed
    assert "resolution" in breaking.lower() and "_incompleteReason" in breaking
