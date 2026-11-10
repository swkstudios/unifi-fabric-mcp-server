"""With ``UNIFI_AUDIT_CHAIN`` unset or false the audit stream is
byte-identical to 0.7.1.

The fixtures in ``tests/fixtures/audit_golden_071/`` were written by :func:`scenario`
running against the 0.7.1 code (integration/0.7.1 at ffb09e3, before the chain existed).
The scenario emits every event type (``startup``, ``audit``, ``call``, ``error``,
``audit.recovered``), both policy records, a sink fault and recovery, a record cut by a
fault (the ``_partial`` newline prefix), and hostile values (a lone surrogate, C1 and DEL,
U+2028/U+2029, a float, non-ASCII text and a scrubbed secret), in both formats at every
level. Time and durations are pinned so the output is deterministic.
"""

from __future__ import annotations

import errno
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import unifi_fabric.audit as audit
from unifi_fabric.audit import AuditStream, FileSink, audit_call, build_audit_stream
from unifi_fabric.config import Settings

FIXTURES = Path(__file__).parent / "fixtures" / "audit_golden_071"
# Registered with the stream and scrubbed from every record; derived at run time so no
# secret-shaped literal sits in the source.
SECRET = "synthetic-golden-secret-" + hashlib.sha256(b"scrub-marker-golden").hexdigest()[:6]
FIXED = datetime(2026, 11, 7, 12, 0, 0, 123456, tzinfo=UTC)
POLICY_STARTUP = (
    '{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",'
    '"effective_policy":{"write_policy":"allow"},"event":"policy.startup",'
    '"schema_version":"1","timestamp_utc":"2026-11-07T12:00:00.000001+00:00"}'
)
POLICY_REFUSAL = (
    '{"code":"invalid_policy_header","event":"policy.refusal",'
    '"request_id":"0123456789abcdef0123456789abcdef","schema_version":"1",'
    '"timestamp_utc":"2026-11-07T12:00:00.000002+00:00","tool_id":null,"upstream_calls":0}'
)
HOSTILE = "lone\ud800 c1\x85 del\x7f ls  ps  café 中 " + SECRET
CASES = [(fmt, level) for fmt in ("json", "text") for level in ("off", "normal", "debug")]


class _FixedDatetime(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # noqa: ARG003 - fixed clock
        return FIXED


def _pin_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "datetime", _FixedDatetime)
    monkeypatch.setattr(audit, "perf_counter", lambda: 1.0)


def scenario(stream: AuditStream, monkeypatch: pytest.MonkeyPatch) -> None:
    """One fixed sequence of every record kind, a fault and a cut record."""
    _pin_clock(monkeypatch)
    stream.startup("0.0.0-golden")
    stream.policy_record(POLICY_STARTUP)
    with audit_call("golden_tool"):
        stream.record(
            method="POST",
            path=f"/proxy/network/api/s/default/{SECRET}?q=1",
            outcome="refused",
            status=None,
            reason=HOSTILE,
            body={"name": HOSTILE, "ratio": 0.25, "password": "x", "n": [1, 2.5, None]},
        )
        stream.call("golden_tool", {"arg": HOSTILE, "f": 1.5})
        stream.error("golden_tool", ValueError(HOSTILE))
    stream.policy_record(POLICY_REFUSAL)

    real_write = os.write

    def enospc(fd: int, data: Any) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit.os, "write", enospc)
    stream.record(method="PUT", path="/lost", outcome="success", status=200)
    stream.policy_record(POLICY_REFUSAL)
    monkeypatch.setattr(audit.os, "write", real_write)
    stream.record(method="DELETE", path="/after-fault", outcome="http_404", status=404)

    calls = {"n": 0}

    def cut(fd: int, data: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            return real_write(fd, bytes(data)[:10])
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(audit.os, "write", cut)
    stream.record(method="PATCH", path="/cut", outcome="success", status=200)
    monkeypatch.setattr(audit.os, "write", real_write)
    stream.record(method="POST", path="/after-cut", outcome="dry_run", status=None)
    stream.probe()


def run_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str, level: str) -> bytes:
    log = tmp_path / f"{fmt}-{level}.log"
    stream = AuditStream(
        sink=FileSink(str(log)), fmt=fmt, level=level, calls=True, secrets=(SECRET,)
    )
    scenario(stream, monkeypatch)
    return log.read_bytes()


@pytest.mark.parametrize(("fmt", "level"), CASES)
def test_stream_without_chain_is_byte_identical_to_071(tmp_path, monkeypatch, fmt, level):
    expected = (FIXTURES / f"{fmt}-{level}.log").read_bytes()
    assert run_case(tmp_path, monkeypatch, fmt, level) == expected


@pytest.mark.parametrize("chain_env", [None, "", "false", "0", "off"])
@pytest.mark.parametrize(("fmt", "level"), CASES)
def test_settings_built_stream_without_chain_is_byte_identical_to_071(
    tmp_path, monkeypatch, fmt, level, chain_env
):
    """The stream ``build_audit_stream`` makes from settings, with ``UNIFI_AUDIT_CHAIN``
    unset or false, writes the 0.7.1 bytes."""
    if chain_env is None:
        monkeypatch.delenv("UNIFI_AUDIT_CHAIN", raising=False)
    else:
        monkeypatch.setenv("UNIFI_AUDIT_CHAIN", chain_env)
    for name in ("UNIFI_AUDIT_SINK", "UNIFI_AUDIT_CHAIN_KEY"):
        monkeypatch.delenv(name, raising=False)
    log = tmp_path / f"{fmt}-{level}.log"
    monkeypatch.setenv("UNIFI_AUDIT_LOG", str(log))
    monkeypatch.setenv("UNIFI_AUDIT_LOG_FORMAT", fmt)
    monkeypatch.setenv("UNIFI_AUDIT_LEVEL", level)
    monkeypatch.setenv("UNIFI_AUDIT_CALLS", "true")
    stream = build_audit_stream(Settings(api_key="synthetic-golden-key"))
    assert stream is not None
    stream.secrets = (SECRET,)
    scenario(stream, monkeypatch)
    assert log.read_bytes() == (FIXTURES / f"{fmt}-{level}.log").read_bytes()
