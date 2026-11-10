"""scripts/check_doc_links.py makes no outbound request unless asked to.

Before the fix every run (and every ``check()`` call) probed each external documentation
link over HTTP, so a test or a lane that ran the checker called out. Now the default is
offline: current-release links are still checked against the working tree, external links
are requested only with ``--external`` (or ``check(..., external=True)``), and inside a
GitHub Actions run, where the documentation workflows call the script, unless
``--offline`` is given. Every outbound path is replaced by a failing stub here.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_doc_links as links  # noqa: E402

EXTERNAL = "https://example.com/docs/guide.md"
RELEASE = "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/README.md"
REPOSITORY = "https://github.com/example/repository"


def _no_network(*_args, **_kwargs):
    raise AssertionError("unexpected outbound request")


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.7.0"\n')
    (tmp_path / "README.md").write_text(
        f"# Project\n[guide]({EXTERNAL})\n[readme]({RELEASE})\n[repo]({REPOSITORY})\n"
    )
    monkeypatch.setattr(links, "ROOT", tmp_path)
    monkeypatch.setattr(links, "urlopen", _no_network)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    return tmp_path


def test_check_is_offline_by_default(project):
    (result,) = links.check(project)
    assert result["url"] == RELEASE
    assert result["ok"] is True and result["source"] == "working-tree"


def test_cli_default_is_offline_and_says_so(project, capsys):
    assert links.main([]) == 0
    out = capsys.readouterr().out
    assert "external links: 1 checked, 0 failed" in out
    assert "offline: 2 external links not requested; pass --external to check them" in out


def test_cli_report_default_is_offline(project, tmp_path):
    report = tmp_path / "report.json"
    with patch.object(links, "archive_state", side_effect=_no_network):
        assert links.main(["--report", str(report)]) == 0
    data = json.loads(report.read_text())
    assert [r["url"] for r in data["links"]] == [RELEASE]
    assert data["repositories"] == []


def test_external_flag_requests_external_links(project, capsys):
    seen: list[str] = []

    def probe(url, retries=2):
        seen.append(url)
        return {"url": url, "status": 200, "ok": True, "moved": False}

    with patch.object(links, "probe", side_effect=probe):
        assert links.main(["--external"]) == 0
    assert sorted(seen) == sorted([EXTERNAL, REPOSITORY])
    assert "external links: 3 checked, 0 failed" in capsys.readouterr().out


@pytest.mark.parametrize(("argv", "requested"), [([], True), (["--offline"], False)])
def test_github_actions_requests_external_links_unless_offline(
    project, monkeypatch, argv, requested
):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with patch.object(
        links, "probe", return_value={"url": EXTERNAL, "status": 200, "ok": True, "moved": False}
    ) as probe:
        assert links.main(argv) == 0
    assert probe.called is requested


def test_external_and_offline_are_mutually_exclusive(project):
    with pytest.raises(SystemExit):
        links.main(["--external", "--offline"])


def test_the_developer_portal_landing_link_is_not_frozen_at_a_version():
    """https://developer.ui.com answers 307 (a temporary redirect) to the current Network
    version's page, so the stable URL is the one to publish: replacing it with the redirect
    target pins the link to one version for good. The link checker follows the redirect and
    reports it as moved, which does not fail the check, so nothing needs the pin."""
    for name in ("CLIENT-SETUP.md", "COVERAGE.md"):
        text = (ROOT / "docs" / name).read_text()
        found = re.findall(r"\[developer\.ui\.com\]\((https://developer\.ui\.com[^)]*)\)", text)
        assert found, f"{name} no longer links the developer portal"
        assert set(found) == {"https://developer.ui.com"}, f"{name} pins a redirect target"
