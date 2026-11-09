"""A JSON audit record is scrubbed value by value before it is encoded, so it stays valid
JSON with its metadata preserved. The metadata-equal credential conflict remains
an unresolved contract, distinct from these baseline JSON metadata checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unifi_fabric.audit import AuditSink


# Raw short secrets are matched. The fragment minimum concerns embedded base64 only.
# These baseline checks preserve the metadata contract; they do not prove nonexposure
# for a configured credential equal to that metadata.
@pytest.mark.parametrize("secret", ["2", "0", "20", "200", "502", "status", "method"])
def test_numeric_secret_never_corrupts_status_or_duration(tmp_path: Path, secret: str) -> None:
    log = tmp_path / "audit.jsonl"
    sink = AuditSink(path=str(log), fmt="json", secrets=(secret,))
    for status in (200, 502, None):
        sink.record(method="PATCH", path="/proxy/x", outcome="refused", status=status)
    records = [
        r
        for r in (json.loads(line) for line in log.read_text().splitlines())
        if r.get("event", "audit") == "audit"
    ]
    assert [r["status"] for r in records] == [200, 502, None]
    assert all(isinstance(r["status"], (int, type(None))) for r in records)
    assert [r["method"] for r in records] == ["PATCH"] * 3


@pytest.mark.parametrize("secret", ["hunter2-credential", 'pa"ss\\word', "tab\tvalue"])
def test_string_fields_are_scrubbed_before_encoding(tmp_path: Path, secret: str) -> None:
    log = tmp_path / "audit.jsonl"
    # "outcome" is a field name: a scrub of the serialized line would mask the key.
    sink = AuditSink(path=str(log), fmt="json", secrets=(secret, "outcome"))
    sink.record(
        method="PATCH",
        path=f"/proxy/x?k={secret}",
        outcome="refused",
        status=None,
        tool="update_x",
        reason=f"bad value {secret} sent",
    )
    raw = log.read_text()
    record = json.loads(raw)
    assert secret not in raw
    assert secret not in json.dumps(record)
    assert secret not in record["path"]
    assert secret not in record["reason"]
    assert record["tool"] == "update_x"
    assert record["method"] == "PATCH"
    assert record["outcome"] == "refused"


def test_text_audit_line_still_never_holds_the_secret(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt="text", secrets=("hunter2-credential", "outcome"))
    sink.record(
        method="PATCH", path="/p?k=hunter2-credential", outcome="refused", status=None, reason="x"
    )
    text = log.read_text()
    assert "hunter2-credential" not in text
    assert "outcome" not in text
    assert " ***=refused status=- reason=x" in text
