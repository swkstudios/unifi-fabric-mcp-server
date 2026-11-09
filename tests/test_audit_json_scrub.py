"""A JSON audit line stays valid JSON whatever secret is configured.

Each case configures a secret that collides with a number or a field name of the record,
so it detects code that scrubs the serialized line instead of the values. Raw short
secrets are matched; the fragment minimum applies only to embedded base64 fragments.
The metadata-collision nonexposure conflict remains unresolved; these tests retain
the baseline JSON metadata contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unifi_fabric.audit import AuditSink


@pytest.mark.parametrize("secret", ["2", "0", "20", "5", "200", "502", "status", "timestamp"])
def test_json_audit_line_is_valid_json_when_a_secret_matches_a_number(tmp_path: Path, secret: str):
    log = tmp_path / "audit.jsonl"
    sink = AuditSink(path=str(log), fmt="json", secrets=(secret,))
    for status in (200, 502, None):
        sink.record(method="PATCH", path="/proxy/x", outcome="success", status=status)
    records = [
        r
        for r in (json.loads(line) for line in log.read_text().splitlines())
        if r.get("event", "audit") == "audit"
    ]
    assert [r["status"] for r in records] == [200, 502, None]
    for record in records:
        assert set(record) >= {"timestamp_utc", "method", "path", "outcome", "status"}


def test_text_audit_line_scrubs_values_and_colliding_field_name(tmp_path: Path):
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt="text", secrets=("hunter2-credential", "status"))
    sink.record(
        method="PATCH", path="/p?k=hunter2-credential", outcome="refused", status=None, reason="x"
    )
    text = log.read_text()
    assert "hunter2-credential" not in text
    assert "status" not in text
    assert " outcome=refused ***=- reason=x" in text


@pytest.mark.parametrize("secret", ['pa"ss\\word-credential', "hunter2-credential"])
def test_json_audit_line_still_scrubs_every_string_field(tmp_path: Path, secret: str):
    log = tmp_path / "audit.jsonl"
    # "403" is the status: a scrub of the serialized line would mask the number.
    sink = AuditSink(path=str(log), fmt="json", secrets=(secret, "403"))
    sink.record(
        method="PATCH",
        path=f"/p?k={secret}",
        outcome="refused",
        status=403,
        tool=f"t-{secret}",
        reason=f"bad {secret}",
    )
    text = log.read_text()
    record = json.loads(text)
    assert secret not in text
    assert secret not in json.dumps(record)
    for field in ("path", "tool", "reason"):
        assert record[field] != ""
        assert secret not in record[field]
    assert record["status"] == 403


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("delimiter", ["?", "#"])
def test_audit_path_secret_spanning_delimiter_is_masked_and_query_omitted(
    tmp_path: Path, fmt: str, delimiter: str
):
    log = tmp_path / "audit.log"
    secret = f"synthetic-leading{delimiter}synthetic-trailing"
    AuditSink(path=str(log), fmt=fmt, secrets=(secret,)).record(
        method="POST", path=f"/route/{secret}extra-query", outcome="success", status=200
    )
    line = log.read_text()
    assert "synthetic-leading" not in line
    assert "synthetic-trailing" not in line
    assert "extra-query" not in line
    if fmt == "json":
        assert json.loads(line)["path"] == "***"
