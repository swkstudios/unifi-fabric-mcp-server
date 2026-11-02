"""The removed request deadline must be visible in release notes."""

from pathlib import Path


def test_removed_request_deadline_has_breaking_release_note() -> None:
    root = Path(__file__).resolve().parents[1]
    changelog = (root / "CHANGELOG.md").read_text()
    current = changelog.split("## [0.7.0]", 1)[1].split("\n## [", 1)[0]
    fragments = "\n".join(
        path.read_text() for path in (root / "changelog.d").glob("*.md") if path.name != "README.md"
    )
    notes = current + "\n" + fragments
    matching = [line for line in notes.splitlines() if "UNIFI_REQUEST_TIMEOUT_SECONDS" in line]
    assert any(
        "**Breaking (configuration)**" in line
        and "startup fails" in line
        and "no HTTP deadline" in line
        and "completion/cancellation" in line
        and "docs/MIGRATING-0.7.md#request-deadline-compatibility" in line
        for line in matching
    )


def test_python_client_api_migration_covers_legacy_changes() -> None:
    root = Path(__file__).resolve().parents[1]
    migration = (root / "docs/MIGRATING-0.7.md").read_text()
    section = migration.split("## Python client API", 1)[1]
    for required in (
        "get_bytes",
        "get_binary",
        "Content-Type",
        "application/octet-stream",
        "non-JSON",
        "max_retries=None",
        "five retries",
        "zero",
        "gather",
        "cancels sibling",
    ):
        assert required in section
