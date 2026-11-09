"""Validate future release links locally without weakening external link checks."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.changelog_section import sections

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_doc_links as links  # noqa: E402

PUBLIC = "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/"


@pytest.fixture
def project(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.7.0"\n')
    (tmp_path / "README.md").write_text("# Project\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "Guide space.md").write_text(
        "# Tool categories\n## Duplicate\n## Duplicate\n"
        "```markdown\n## Fenced heading\n```\n"
        '<a id="explicit-id"></a>\n'
    )
    return tmp_path


@pytest.mark.parametrize(
    "fragment", ["", "#tool-categories", "#tool%2Dcategories", "#duplicate-1", "#explicit-id"]
)
def test_current_release_paths_and_headings_are_checked_without_http(project, fragment):
    url = PUBLIC + "v0.7.0/docs/Guide%20space.md" + fragment
    (project / "README.md").write_text(f"[guide]({url})\n")
    with patch.object(links, "probe", side_effect=AssertionError("unexpected HTTP request")):
        (result,) = links.check(project)
    assert result == {
        "url": url,
        "status": 200,
        "ok": True,
        "moved": False,
        "source": "working-tree",
    }


@pytest.mark.parametrize(
    "target, reason",
    [
        ("missing.md", "target does not exist"),
        ("docs/", "target does not exist"),
        ("docs/Guide%20space.md#missing", "fragment does not match"),
        ("docs/Guide%20space.md#fenced-heading", "fragment does not match"),
        ("../README.md", "target does not exist"),
        ("%2Fetc%2Fhosts", "target does not exist"),
    ],
)
def test_missing_release_files_and_headings_fail_without_http(project, target, reason):
    url = PUBLIC + "v0.7.0/" + target
    (project / "README.md").write_text(f"[guide]({url})\n")
    with patch.object(links, "probe", side_effect=AssertionError("unexpected HTTP request")):
        (result,) = links.check(project)
    assert result["ok"] is False
    assert result["status"] == 404
    assert reason in result["reason"]


@pytest.mark.parametrize(
    "url",
    [
        PUBLIC + "v0.6.4/docs/guide.md",
        PUBLIC + "v0.7.0rc1/docs/guide.md",
        PUBLIC + "main/docs/guide.md",
        PUBLIC + "v0.7.0/docs/guide.md?raw=1",
        (PUBLIC + "v0.7.0/docs/guide.md").replace("https:", "http:"),
        (PUBLIC + "v0.7.0/docs/guide.md").replace("swkstudios", "someone-else"),
        (PUBLIC + "v0.7.0/docs/guide.md").replace("github.com/", "github.com.example/"),
        "https://example.com/docs/guide.md#section",
    ],
)
def test_other_external_links_keep_existing_http_probe(project, url):
    (project / "README.md").write_text(f"[guide]({url})\n")
    expected = {"url": url, "status": 503, "ok": False, "moved": False}
    with patch.object(links, "probe", return_value=expected) as probe:
        assert links.check(project, retries=1, external=True) == [expected]
    probe.assert_called_once_with(url, retries=1)


def test_version_is_read_from_pyproject_and_missing_version_does_not_bypass_http(project):
    url = PUBLIC + "v1.2.3/docs/Guide%20space.md#tool-categories"
    (project / "README.md").write_text(f"[guide]({url})\n")
    (project / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    with patch.object(links, "probe", side_effect=AssertionError("unexpected HTTP request")):
        assert links.check(project, external=True)[0]["ok"] is True
    (project / "pyproject.toml").write_text("[project]\n")
    with patch.object(links, "probe", return_value={"ok": False}) as probe:
        assert links.check(project, external=True) == [{"ok": False}]
    probe.assert_called_once_with(url, retries=2)


def test_release_body_and_pypi_readme_links_are_both_discovered(project):
    readme = "https://example.com/pypi-readme"
    release = PUBLIC + "v0.7.0/docs/Guide%20space.md#tool-categories"
    (project / "README.md").write_text(f"[readme]({readme})\n")
    (project / "CHANGELOG.md").write_text(
        "# Changelog\n## [Unreleased]\n[future](https://example.com/future)\n"
        f"## [0.7.0] - date\n[release]({release})\n"
        "## [0.6.4] - date\n[old](https://example.com/old)\n"
    )
    assert links.urls(project) == sorted([readme, release])


def test_rendered_release_and_pypi_docs_have_valid_current_release_links():
    """Audit both rendered entry points using their actual packaging/release inputs."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["project"]["readme"] == "README.md"
    texts = links.reference_texts(ROOT)
    assert (ROOT / "README.md").read_text() in texts
    # The release body is the package version's section once it is open, else the
    # published release's: the same choice reference_texts makes.
    changelog = {
        name: body.removeprefix("\n")
        for name, _heading, body in sections((ROOT / "CHANGELOG.md").read_text())
    }
    version = config["project"]["version"]
    if version not in changelog:
        version = (ROOT / "scripts/published-version.txt").read_text().strip()
    release = changelog[version]
    assert release in texts
    rendered = [
        text.replace("swkstudios/unifi-fabric-mcp-server", "swkstudios/unifi-fabric-mcp-server")
        for text in ((ROOT / "README.md").read_text(), release)
    ]
    with patch.object(links, "reference_texts", return_value=rendered):
        targets = links.urls(ROOT)
    checked = [
        result
        for url in targets
        if (result := links.current_release_link(url, ROOT, version)) is not None
    ]
    assert checked, "the current release must retain absolute, tag-pinned documentation links"
    assert all(result["ok"] for result in checked), checked


def _http_error(url: str, code: int):
    from urllib.error import HTTPError

    return HTTPError(url, code, "status", {}, None)


def test_rate_limit_on_every_attempt_is_not_tested_rather_than_passed(capsys):
    url = "https://example.invalid/page"
    with (
        patch.object(links, "urlopen", side_effect=_http_error(url, 429)) as opener,
        patch.object(links.time, "sleep"),
    ):
        result = links.probe(url, retries=2)
    assert opener.call_count == 3
    assert result["ok"] is False
    assert result["not_tested"] == "rate limited (HTTP 429) on all 3 attempts"

    broken = {"url": "https://example.invalid/gone", "status": 404, "ok": False, "moved": False}
    with (
        patch.object(links, "discovery", return_value=([url, broken["url"]], [])),
        patch.object(links, "check", return_value=[result, broken]),
    ):
        assert links.main(["--external"]) == 1
    out = capsys.readouterr().out
    assert f"NOT-TESTED: {url}: rate limited" in out
    assert f"broken external link: {url}" not in out
    assert "external links: 1 checked, 1 failed, 1 not tested" in out

    with (
        patch.object(links, "discovery", return_value=([url], [])),
        patch.object(links, "check", return_value=[result]),
    ):
        assert links.main(["--external"]) == 0


def test_community_documents_and_issue_templates_are_discovered(project):
    issue_dir = project / ".github" / "ISSUE_TEMPLATE"
    issue_dir.mkdir(parents=True)
    (project / "CONTRIBUTING.md").write_text("[contribute](https://example.com/contribute)")
    (issue_dir / "bug.md").write_text("[bug](https://example.com/bug)")
    assert "https://example.com/contribute" in links.urls(project)
    assert "https://example.com/bug" in links.urls(project)


def test_markdown_link_followed_by_colon_is_discovered_once(project):
    url = "https://www.conventionalcommits.org/"
    (project / "CONTRIBUTING.md").write_text(f"See [conventions]({url}): details.\n")
    assert links.urls(project) == [url]
