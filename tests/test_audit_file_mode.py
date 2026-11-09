"""Audit file handling (CodeQL py/clear-text-storage-sensitive-data on audit.py)."""

from __future__ import annotations

import os
import stat

import pytest

from unifi_fabric.audit import AuditSink


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_new_audit_file_is_owner_only(tmp_path):
    path = tmp_path / "audit.log"
    old = os.umask(0o022)
    try:
        AuditSink(path=str(path)).record(method="POST", path="/x", outcome="ok", status=200)
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8").count("\n") == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_existing_audit_file_keeps_its_mode_and_appends(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("first\n", encoding="utf-8")
    path.chmod(0o640)
    AuditSink(path=str(path), fmt="json").record(
        method="DELETE", path="/y?k=v", outcome="ok", status=204
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "first" and '"path":"/y"' in lines[1]


def test_unwritable_audit_path_is_not_fatal(tmp_path, caplog):
    target = tmp_path / "missing-dir" / "audit.log"
    AuditSink(path=str(target)).record(method="POST", path="/x", outcome="ok", status=200)
    assert not target.exists()
    assert "audit sink file unavailable (ENOENT)" in caplog.text
