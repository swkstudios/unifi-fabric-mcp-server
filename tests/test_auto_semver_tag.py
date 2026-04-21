"""Tests for scripts/auto_semver_tag.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts/ to sys.path so we can import the module directly
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import auto_semver_tag as ast_mod  # noqa: E402

# ---------------------------------------------------------------------------
# bump_patch
# ---------------------------------------------------------------------------


def test_bump_patch_basic():
    assert ast_mod.bump_patch("0.2.1") == "0.2.2"


def test_bump_patch_zero():
    assert ast_mod.bump_patch("1.0.0") == "1.0.1"


def test_bump_patch_large():
    assert ast_mod.bump_patch("3.14.99") == "3.14.100"


def test_bump_patch_bad_format():
    with pytest.raises(SystemExit, match="Unexpected version format"):
        ast_mod.bump_patch("1.2")


# ---------------------------------------------------------------------------
# read_version / write_version
# ---------------------------------------------------------------------------


def test_read_version(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "0.2.1"\n')
    with patch.object(ast_mod, "PYPROJECT", pyproject):
        assert ast_mod.read_version() == "0.2.1"


def test_write_version(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "0.2.1"\n')
    with patch.object(ast_mod, "PYPROJECT", pyproject):
        ast_mod.write_version("0.2.2")
        assert pyproject.read_text() == '[project]\nversion = "0.2.2"\n'


def test_write_version_dry_run(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    original = '[project]\nversion = "0.2.1"\n'
    pyproject.write_text(original)
    with patch.object(ast_mod, "PYPROJECT", pyproject):
        # read_version called inside write_version — mock it too
        with patch.object(ast_mod, "read_version", return_value="0.2.1"):
            ast_mod.write_version("0.2.2", dry_run=True)
    # File must remain unchanged in dry-run
    assert pyproject.read_text() == original


def test_write_version_no_version_line(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'foo'\n")
    with patch.object(ast_mod, "PYPROJECT", pyproject):
        with pytest.raises(SystemExit, match="Could not find version line"):
            ast_mod.write_version("0.2.2")


# ---------------------------------------------------------------------------
# current_branch / tag_exists
# ---------------------------------------------------------------------------


def test_current_branch(monkeypatch):
    fake_result = MagicMock(stdout="dev\n", returncode=0)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)
    assert ast_mod.current_branch() == "dev"


def test_tag_exists_true(monkeypatch):
    fake_result = MagicMock(stdout="v0.2.1\n", returncode=0)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)
    assert ast_mod.tag_exists("v0.2.1") is True


def test_tag_exists_false(monkeypatch):
    fake_result = MagicMock(stdout="", returncode=0)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)
    assert ast_mod.tag_exists("v0.2.1") is False


# ---------------------------------------------------------------------------
# run() helper
# ---------------------------------------------------------------------------


def test_run_dry_run():
    result = ast_mod.run(["git", "status"], dry_run=True)
    assert result.returncode == 0


def test_run_executes(monkeypatch):
    fake_result = MagicMock(returncode=0, stdout="", stderr="")
    calls = []

    def fake_subprocess_run(cmd, **kw):
        calls.append(cmd)
        return fake_result

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    ast_mod.run(["git", "status"])
    assert ["git", "status"] in calls


def test_run_failure_exits(monkeypatch):
    fake_result = MagicMock(returncode=1, stdout="", stderr="error")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)
    with pytest.raises(SystemExit):
        ast_mod.run(["git", "bad-command"])


# ---------------------------------------------------------------------------
# main() integration
# ---------------------------------------------------------------------------


def _make_fake_run(calls: list):
    """Return a patched run() that records calls without executing anything."""

    def fake_run(cmd, *, dry_run=False, capture=False):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    return fake_run


def test_main_happy_path(tmp_path, monkeypatch):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "0.2.1"\n')

    run_calls: list = []

    monkeypatch.setattr(ast_mod, "PYPROJECT", pyproject)
    monkeypatch.setattr(ast_mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(ast_mod, "current_branch", lambda: "dev")
    monkeypatch.setattr(ast_mod, "tag_exists", lambda _: False)
    monkeypatch.setattr(ast_mod, "configure_github_app_auth", lambda **kw: None)
    monkeypatch.setattr(ast_mod, "run", _make_fake_run(run_calls))

    monkeypatch.setattr(sys, "argv", ["auto_semver_tag.py"])
    ast_mod.main()

    # Version file updated
    assert "0.2.2" in pyproject.read_text()

    # Git commands issued
    assert any("commit" in str(c) for c in run_calls)
    assert any("tag" in str(c) for c in run_calls)
    assert any("push" in str(c) for c in run_calls)


def test_main_dry_run(tmp_path, monkeypatch):
    pyproject = tmp_path / "pyproject.toml"
    original = '[project]\nversion = "0.2.1"\n'
    pyproject.write_text(original)

    run_calls: list = []

    monkeypatch.setattr(ast_mod, "PYPROJECT", pyproject)
    monkeypatch.setattr(ast_mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(ast_mod, "current_branch", lambda: "dev")
    monkeypatch.setattr(ast_mod, "tag_exists", lambda _: False)
    monkeypatch.setattr(ast_mod, "configure_github_app_auth", lambda **kw: None)
    monkeypatch.setattr(ast_mod, "run", _make_fake_run(run_calls))

    monkeypatch.setattr(sys, "argv", ["auto_semver_tag.py", "--dry-run"])
    ast_mod.main()

    # File must be untouched in dry-run
    assert pyproject.read_text() == original


def test_main_wrong_branch(monkeypatch):
    monkeypatch.setattr(ast_mod, "current_branch", lambda: "main")
    monkeypatch.setattr(sys, "argv", ["auto_semver_tag.py"])
    with pytest.raises(SystemExit, match="dev"):
        ast_mod.main()


def test_main_idempotent(monkeypatch):
    monkeypatch.setattr(ast_mod, "current_branch", lambda: "dev")
    monkeypatch.setattr(ast_mod, "read_version", lambda: "0.2.1")
    monkeypatch.setattr(ast_mod, "tag_exists", lambda _: True)  # tag already exists
    monkeypatch.setattr(sys, "argv", ["auto_semver_tag.py"])

    # Should not raise or call write_version / run
    ran_write = []
    monkeypatch.setattr(ast_mod, "write_version", lambda *a, **kw: ran_write.append(1))
    ast_mod.main()
    assert ran_write == []
