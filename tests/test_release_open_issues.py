"""scripts/release_open_issues.py lists open release-labelled issues; it is not a gate."""

from __future__ import annotations

import json
import subprocess

import pytest

from scripts import release_open_issues as roi

ISSUES = [
    {"number": 9, "title": "later", "url": "u9", "labels": [{"name": "release:1.2.3"}]},
    {"number": 3, "title": "first", "url": "u3", "labels": [{"name": "release:1.2.3"}]},
]


class Fake:
    def __init__(self, out="[]", code=0, err=""):
        self.calls: list[list[str]] = []
        self.result = subprocess.CompletedProcess([], code, out, err)

    def __call__(self, cmd):
        self.calls.append(cmd)
        return self.result


def test_it_asks_gh_for_open_issues_with_the_version_label_only():
    fake = Fake(json.dumps(ISSUES))
    found = roi.open_issues("1.2.3", "o/r", fake)
    (cmd,) = fake.calls
    assert cmd[:3] == ["gh", "issue", "list"] and "-R" in cmd and "o/r" in cmd
    assert cmd[cmd.index("--state") + 1] == "open"
    assert cmd[cmd.index("--label") + 1] == "release:1.2.3"
    assert [issue["number"] for issue in found] == [3, 9]


def test_it_is_read_only():
    fake = Fake()
    roi.open_issues("1.2.3", run=fake)
    assert not {"edit", "close", "comment", "create", "delete"} & set(fake.calls[0])


def test_cli_lists_and_exits_zero_even_when_issues_remain(capsys):
    assert roi.main(["1.2.3"], run=Fake(json.dumps(ISSUES))) == 0
    out = capsys.readouterr().out
    assert "2 open issue(s) carry release:1.2.3" in out
    assert out.index("#3  first") < out.index("#9  later")


def test_cli_with_nothing_open_exits_zero(capsys):
    assert roi.main(["1.2.3"], run=Fake("[]")) == 0
    assert "No open issues carry release:1.2.3." in capsys.readouterr().out


def test_cli_count_and_json(capsys):
    assert roi.main(["1.2.3", "--count"], run=Fake(json.dumps(ISSUES))) == 0
    assert capsys.readouterr().out.strip() == "2"
    assert roi.main(["1.2.3", "--json"], run=Fake(json.dumps(ISSUES))) == 0
    assert [i["number"] for i in json.loads(capsys.readouterr().out)] == [3, 9]


def test_the_default_version_is_the_pyproject_version(capsys):
    fake = Fake()
    assert roi.main([], run=fake) == 0
    assert fake.calls[0][fake.calls[0].index("--label") + 1] == f"release:{roi.project_version()}"


@pytest.mark.parametrize(
    "fake",
    [Fake(code=1, err="HTTP 401"), Fake(out="not json"), Fake(out='{"a": 1}')],
    ids=["gh-failed", "unreadable", "not-a-list"],
)
def test_a_failed_lookup_is_exit_2_never_an_empty_list(fake, capsys):
    assert roi.main(["1.2.3"], run=fake) == 2
    assert "release_open_issues:" in capsys.readouterr().err


def test_a_malformed_version_is_refused_before_gh_runs(capsys):
    fake = Fake()
    assert roi.main(["v0.7"], run=fake) == 2
    assert fake.calls == []
