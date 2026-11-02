"""Text audit records scrub values before encoding and the complete assembled line.

Metadata that collides with a configured secret is redacted under the original text
contract. Noncolliding records retain their readable fields and original safety checks.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

import unifi_fabric.audit as audit
from unifi_fabric.audit import AuditSink
from unifi_fabric.secret_scrub import contains_secret, scrub

#: One text record: timestamp, then key=value fields (a value plain or JSON-quoted).
FIELD = re.compile(r' ([A-Za-z_]+)=("(?:[^"\\]|\\.)*"|\S+)')


def _fields(line: str) -> dict[str, str]:
    ts, _, rest = line.partition(" ")
    assert ts
    fields = dict(FIELD.findall(" " + rest))
    assert " ".join(f"{k}={v}" for k, v in fields.items()) == rest
    return fields


@pytest.mark.parametrize("secret", ["2", "0", "20", "200", "502", "status", "path", "outcome"])
def test_text_metadata_collisions_use_completed_line_scrub(
    tmp_path: Path, monkeypatch, secret: str
) -> None:
    class FixedDatetime:
        @staticmethod
        def now(tz):
            assert tz is UTC
            return datetime(2026, 10, 28, tzinfo=UTC)

    monkeypatch.setattr(audit, "datetime", FixedDatetime)
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt="text", secrets=(secret,))
    expected = []
    for status in (200, 502):
        sink.record(
            method="PATCH",
            path="/proxy/x",
            outcome="refused",
            status=status,
            tool="update_x",
            reason="UNIFI_READ_ONLY",
        )
        expected.append(
            scrub(
                f"{scrub('2026-10-28T00:00:00+00:00', (secret,))} method=PATCH "
                f"path=/proxy/x outcome=refused status={status} "
                "tool=update_x reason=UNIFI_READ_ONLY",
                (secret,),
            )
        )
    lines = log.read_text().splitlines()
    assert lines == expected
    assert len(lines) == 2
    assert all(not contains_secret(line, (secret,)) for line in lines)
    assert all("method=PATCH" in line and "tool=update_x" in line for line in lines)


@pytest.mark.parametrize(
    ("secret", "path"),
    [
        ("path=/synthetic-credential-example", "/synthetic-credential-example"),
        ("/synthetic-credential-example outcome=refused", "/synthetic-credential-example"),
    ],
)
def test_text_scrubs_secrets_assembled_across_fields(
    tmp_path: Path, secret: str, path: str
) -> None:
    log = tmp_path / "audit.log"
    AuditSink(path=str(log), fmt="text", secrets=(secret,)).record(
        method="PATCH",
        path=path,
        outcome="refused",
        status=403,
    )
    raw = log.read_text()
    assert len(raw.splitlines()) == 1
    assert secret not in raw
    assert not contains_secret(raw, (secret,))
    assert " method=PATCH " in raw and " status=403" in raw


@pytest.mark.parametrize("secret", ["hunter2-credential", 'pa"ss\\word', "tab\tvalue"])
def test_text_string_fields_are_scrubbed_before_formatting(tmp_path: Path, secret: str) -> None:
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt="text", secrets=(secret,))
    sink.record(
        method="PATCH",
        path=f"/proxy/x?k={secret}",
        outcome="refused",
        status=None,
        tool=f"update_{secret}",
        reason=f"bad value {secret} sent",
    )
    raw = log.read_text()
    assert secret not in raw
    fields = _fields(raw.rstrip("\n"))
    assert fields["method"] == "PATCH"
    assert fields["status"] == "-"
    assert secret not in fields["path"] and secret not in fields["reason"]
    assert secret not in fields["tool"]
