"""scripts/check_retired_settings.py: the retired-setting lint over a synthetic tree.

Every name here is synthetic (``UNIFI_EXAMPLE_*``); the real migration table lives only
in the changelog, which is the rule this lint enforces.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_retired_settings.py"
GIT = shutil.which("git") or "git"

_spec = importlib.util.spec_from_file_location("check_retired_settings", SCRIPT)
assert _spec and _spec.loader
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)

TABLE = (
    "- **Breaking (configuration)** Synthetic settings change.\n"
    "- Retired setting `UNIFI_EXAMPLE_RETIRED`: replace it with `UNIFI_EXAMPLE_NEW=deny`.\n"
    "- Retired setting `UNIFI_EXAMPLE_OTHER`: rename it to `UNIFI_EXAMPLE_ALLOW`.\n"
)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run([GIT, "init", "-q"], cwd=tmp_path, check=True)  # noqa: S603 - fixed git command
    subprocess.run([GIT, "add", "-A"], cwd=tmp_path, check=True)  # noqa: S603 - fixed git command
    return tmp_path


def test_names_come_from_fragment_and_changelog(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "CHANGELOG.md": "## [0.1.0]\n\n- Retired setting `UNIFI_EXAMPLE_OLDER`: gone.\n",
        },
    )
    assert lint.retired_names(root) == [
        "UNIFI_EXAMPLE_OLDER",
        "UNIFI_EXAMPLE_OTHER",
        "UNIFI_EXAMPLE_RETIRED",
    ]


def test_clean_tree_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "README.md": "Set `UNIFI_EXAMPLE_NEW=deny`.\n",
            # A longer identifier that merely contains a retired name is a different word.
            "docs/a.md": "UNIFI_EXAMPLE_RETIRED_SUFFIX is unrelated.\n",
        },
    )
    assert lint.main(["--root", str(root)]) == 0
    assert "OK (2 retired names" in capsys.readouterr().out


def test_occurrence_fails_with_counts_never_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "src/pkg/config.py": "NAME = 'UNIFI_EXAMPLE_RETIRED'  # secret-looking-value-123\n",
            "docs/guide.md": "UNIFI_EXAMPLE_OTHER=a\nUNIFI_EXAMPLE_OTHER=b\n",
        },
    )
    assert lint.main(["--root", str(root), "--check"]) == 1
    err = capsys.readouterr().err
    assert "docs/guide.md: 2" in err
    assert "src/pkg/config.py: 1" in err
    assert "secret-looking-value-123" not in err
    assert "=a" not in err


def test_changelog_is_excluded(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "CHANGELOG.md": "## [0.1.0]\n\n- Uses UNIFI_EXAMPLE_RETIRED historically.\n",
            "changelog.d/y-2.fixed.md": "- Mentions UNIFI_EXAMPLE_OTHER.\n",
        },
    )
    assert lint.main(["--root", str(root)]) == 0


MARK = lint.CAPTURE_ATTRIBUTE


def test_marked_dated_captures_are_excluded(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "records/run-a/capture-2026-01-02.json": '{"step": "UNIFI_EXAMPLE_RETIRED=1"}\n',
            "records/run-b/live-run.jsonl": '{"UNIFI_EXAMPLE_OTHER": null}\n',
            "records/.gitattributes": (
                f"run-a/capture-2026-01-02.json {MARK}\n/run-b/live-run.jsonl {MARK}\n"
            ),
        },
    )
    assert lint.main(["--root", str(root)]) == 0


def test_unmarked_captures_and_release_notes_are_not_excluded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "records/run-a/capture-2026-01-02.json": '{"step": "UNIFI_EXAMPLE_RETIRED=1"}\n',
            "records/run-a/capture-2026-01-03.json": '{"step": "UNIFI_EXAMPLE_RETIRED=1"}\n',
            "records/.gitattributes": f"run-a/capture-2026-01-02.json {MARK}\n",
            "docs/release-notes/0.1.0.md": "UNIFI_EXAMPLE_OTHER\n",
        },
    )
    assert lint.main(["--root", str(root)]) == 1
    err = capsys.readouterr().err
    assert "records/run-a/capture-2026-01-03.json: 1" in err
    assert "docs/release-notes/0.1.0.md: 1" in err
    assert "capture-2026-01-02" not in err


@pytest.mark.parametrize(
    "marks",
    [
        f"run-a/*.json {MARK}\n",  # a pattern would exempt every future capture
        f"run-a/ {MARK}\n",  # a directory, not a file
        f"run-a/capture-2026-01-09.json {MARK}\n",  # names no tracked file
        f"run-a/capture-2026-01-02.json {MARK}\n** binary {MARK}\n",
        # no slash: the mark reaches a file of that name at any depth
        f"capture-2026-01-02.json {MARK}\n",
    ],
)
def test_capture_mark_that_is_not_one_exact_path_fails_closed(
    tmp_path: Path, marks: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "records/run-a/capture-2026-01-02.json": "{}\n",
            "records/run-b/live.jsonl": "{}\n",
            "records/capture-2026-01-02.json": "{}\n",
            "records/.gitattributes": marks,
        },
    )
    assert lint.main(["--root", str(root)]) == 2
    assert "check_retired_settings: a " in capsys.readouterr().err


def test_lint_names_no_capture_path() -> None:
    # Capture paths live beside the captures, in their .gitattributes; the lint, which
    # ships, carries only public paths and the attribute name.
    text = SCRIPT.read_text(encoding="utf-8")
    assert "evidence" not in text.lower()
    assert all(spec.startswith(":(exclude") for spec in lint.EXCLUDED_PATHSPECS)
    assert f":(exclude,attr:{MARK})" in lint.EXCLUDED_PATHSPECS


def test_match_is_case_insensitive(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {"changelog.d/x-1.changed.md": TABLE, "README.md": "[x](#section-unifi_example_other)\n"},
    )
    assert lint.main(["--root", str(root)]) == 1


def test_anchor_only_alias_lines_are_not_counted(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "README.md": '<a id="section-unifi_example_other"></a>\n\n### Section\n',
        },
    )
    assert lint.main(["--root", str(root)]) == 0


def test_anchor_line_with_more_text_is_counted(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "changelog.d/x-1.changed.md": TABLE,
            "README.md": '<a id="x"></a> Set UNIFI_EXAMPLE_OTHER=1.\n',
        },
    )
    assert lint.main(["--root", str(root)]) == 1


def test_untracked_files_are_ignored(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"changelog.d/x-1.changed.md": TABLE})
    (root / "scratch.md").write_text("UNIFI_EXAMPLE_RETIRED\n", encoding="utf-8")
    assert lint.main(["--root", str(root)]) == 0


def test_missing_table_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"README.md": "nothing here\n"})
    assert lint.main(["--root", str(root)]) == 2
    assert "migration table is missing" in capsys.readouterr().err


def test_script_carries_no_retired_name() -> None:
    names = lint.retired_names(ROOT)
    text = SCRIPT.read_text(encoding="utf-8")
    assert not [name for name in names if name in text]


def test_tracked_tree_names_no_retired_setting() -> None:
    """The real tree: no retired name outside the changelog (lands after the runtime cut)."""
    assert lint.retired_names(ROOT), "the changelog migration table is missing"
    assert lint.find_occurrences(ROOT, lint.retired_names(ROOT)) == {}


def test_no_exclusion_names_the_removed_071_migration_kit() -> None:
    """0.7.2 deleted the 0.7.1 migration kit, so the lint exempts none of its paths."""
    kit = ("MIGRATING-0.7.1", "migrate-0.7.1", "upgrade-0.7.1")
    assert [spec for spec in lint.EXCLUDED_PATHSPECS if any(k in spec for k in kit)] == []
    text = SCRIPT.read_text(encoding="utf-8")
    assert [k for k in kit if k in text] == []
