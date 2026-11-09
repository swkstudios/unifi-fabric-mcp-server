"""Acceptance: the typed audit stream contract.

Covers the event schema and canonical JSON form, the levels (off / normal / debug), the
sinks (none / stderr / file), file creation permissions, a synthetic-secret leak sweep
across every event, level and format, and sink faults with fail-open, the per-response
``audit_unavailable`` notice and recovery. When ``AUDIT_ARTIFACT_DIR`` is set, the
permission, leak and fault tests append one JSON line per case to
``audit-permissions.jsonl``, ``audit-synthetic-leak.jsonl`` and
``audit-sink-faults.jsonl`` there (the acceptance artifacts).
"""

from __future__ import annotations

import errno
import io
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

import unifi_fabric.audit as audit
from unifi_fabric.audit import (
    AUDIT_UNAVAILABLE,
    EVENT_FIELDS,
    FAULT_ERRNOS,
    NOTICE_META_KEY,
    OUTCOME_HTTP,
    OUTCOMES,
    AuditStream,
    FileSink,
    NullSink,
    StderrSink,
    audit_call,
    build_audit_stream,
    canonical_json,
)
from unifi_fabric.config import Settings
from unifi_fabric.redaction import REDACTION_MASK

SECRET = "synthetic-audit-secret-7f3a9c"  # registered; must never appear in any record
UNREGISTERED_CREDENTIAL = "plain-password-value-91be"  # masked by field name only


def _artifact(name: str, row: dict[str, Any]) -> None:
    target = os.environ.get("AUDIT_ARTIFACT_DIR")
    if not target:
        return
    Path(target).mkdir(parents=True, exist_ok=True)
    with (Path(target) / f"{name}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(canonical_json(row) + "\n")


def _settings(**kw: Any) -> Settings:
    return Settings(api_key="synthetic-contract-key", **kw)


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def _stream(tmp_path: Path, **kw: Any) -> tuple[AuditStream, Path]:
    log = tmp_path / "audit.jsonl"
    defaults: dict[str, Any] = {"fmt": "json", "level": "normal", "calls": True}
    defaults.update(kw)
    return AuditStream(sink=FileSink(str(log)), secrets=(SECRET,), **defaults), log


def _every_event(stream: AuditStream) -> None:
    """Emit one record of every event type, each carrying the synthetic secret."""
    stream.startup("0.0.0-test")
    with audit_call(f"tool_{SECRET}"):
        stream.record(
            method="POST",
            path=f"/proxy/network/api/s/default/{SECRET}?token={SECRET}#{SECRET}",
            outcome="refused",
            status=None,
            reason=f"refused: {SECRET}",
            body={"name": SECRET, "password": UNREGISTERED_CREDENTIAL, "x": [SECRET]},
        )
        stream.call(f"tool_{SECRET}", {"q": SECRET, "x_passphrase": UNREGISTERED_CREDENTIAL})
        stream.error(f"tool_{SECRET}", RuntimeError(f"upstream said {SECRET}"))


def _raising(err: int):
    def failing_open(*args: Any, **kwargs: Any) -> int:
        raise OSError(err, os.strerror(err))

    return failing_open


# ------------------------------------------------------------------------ schema / form
def test_every_event_has_exactly_its_field_set_and_canonical_form(tmp_path):
    stream, log = _stream(tmp_path, level="debug")
    _every_event(stream)
    seen = set()
    for line in _lines(log):
        rec = json.loads(line)
        assert line == canonical_json(rec), "not the canonical serialization"
        spec = EVENT_FIELDS[rec["event"]]
        assert set(spec["required"]) <= set(rec), rec["event"]
        assert set(rec) <= set(spec["required"]) | set(spec["optional"]), rec["event"]
        assert rec["schema_version"] == "1"
        assert rec["timestamp_utc"].endswith("+00:00")
        seen.add(rec["event"])
    assert seen == {"startup", "audit", "call", "error"}


def test_recovered_record_has_its_field_set_and_canonical_form(tmp_path, monkeypatch):
    stream, log = _stream(tmp_path)
    real_open = os.open
    monkeypatch.setattr(audit.os, "open", _raising(errno.ENOSPC))
    stream.record(method="POST", path="/lost", outcome="success", status=200)
    monkeypatch.setattr(audit.os, "open", real_open)
    stream.record(method="POST", path="/after", outcome="success", status=200)
    recovered, after = (json.loads(line) for line in _lines(log))
    spec = EVENT_FIELDS["audit.recovered"]
    assert set(recovered) == set(spec["required"])
    assert _lines(log)[0] == canonical_json(recovered)
    # One timestamp for the recovery record and the record that follows it (file order).
    assert recovered["timestamp_utc"] == after["timestamp_utc"]


def test_outcome_vocabulary_matches_the_chokepoint_labels():
    from unifi_fabric.client import _outcome_label

    for status in (None, 200, 204, 301, 404, 500):
        label = _outcome_label(status)
        assert label in OUTCOMES or re.fullmatch(OUTCOME_HTTP, label), label


def test_text_audit_line_keeps_the_070_shape_and_other_events_name_themselves(tmp_path):
    stream, log = _stream(tmp_path, fmt="text")
    stream.startup("0.0.0-test")
    stream.record(method="DELETE", path="/x/1", outcome="success", status=204)
    startup, rec = _lines(log)
    assert " event=startup " in startup
    assert re.fullmatch(r"\S+ method=DELETE path=/x/1 outcome=success status=204", rec)


# ------------------------------------------------------------------------------- levels
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_off_writes_nothing(tmp_path, fmt):
    stream, log = _stream(tmp_path, level="off", fmt=fmt)
    _every_event(stream)
    assert _lines(log) == []
    assert not stream.enabled


def test_normal_is_metadata_only(tmp_path):
    stream, log = _stream(tmp_path, level="normal")
    _every_event(stream)
    recs = [json.loads(line) for line in _lines(log)]
    assert recs and all("body" not in r and "arguments" not in r for r in recs)
    assert all("message" not in r for r in recs if r["event"] == "error")


def test_debug_adds_scrubbed_bodies_only(tmp_path):
    stream, log = _stream(tmp_path, level="debug")
    _every_event(stream)
    recs = {json.loads(line)["event"]: json.loads(line) for line in _lines(log)}
    assert recs["audit"]["body"]["password"] == REDACTION_MASK
    assert recs["audit"]["body"]["name"] == "***"
    assert recs["call"]["arguments"]["x_passphrase"] == REDACTION_MASK
    assert "upstream said" in recs["error"]["message"]


def test_calls_off_writes_no_call_or_error_record(tmp_path):
    stream, log = _stream(tmp_path, calls=False)
    _every_event(stream)
    assert {json.loads(line)["event"] for line in _lines(log)} == {"startup", "audit"}


# --------------------------------------------------------------------- policy records
POLICY_LINES = (
    canonical_json(
        {
            "schema_version": "1",
            "timestamp_utc": "2026-11-03T00:00:00+00:00",
            "event": "policy.startup",
            "effective_policy": {"write_policy": "allow"},
            "digest": "0" * 64,
        }
    ),
    canonical_json(
        {
            "schema_version": "1",
            "timestamp_utc": "2026-11-03T00:00:01+00:00",
            "event": "policy.refusal",
            "request_id": "r1",
            "tool_id": None,
            "code": "invalid_policy_header",
            "upstream_calls": 0,
        }
    ),
)


@pytest.mark.parametrize("level", ["off", "normal", "debug"])
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_policy_records_are_carried_byte_identical_at_every_level(tmp_path, level, fmt):
    stream, log = _stream(tmp_path, level=level, fmt=fmt)
    for line in POLICY_LINES:
        stream.policy_record(line)
    assert _lines(log) == list(POLICY_LINES)


def test_policy_records_add_no_second_copy_on_stderr():
    out = io.StringIO()
    stream = AuditStream(sink=StderrSink(stream=lambda: out), fmt="json")
    for line in POLICY_LINES:
        stream.policy_record(line)
    assert out.getvalue() == ""


# -------------------------------------------------------------------------------- sinks
def test_sink_resolution_and_conflicts(tmp_path):
    assert build_audit_stream(_settings()) is None
    assert build_audit_stream(_settings(audit_sink="none")) is None
    path = str(tmp_path / "a.log")
    file_stream = build_audit_stream(_settings(audit_log=path))
    assert file_stream is not None and isinstance(file_stream.sink, FileSink)
    assert file_stream.fmt == "json" and file_stream.level == "normal"
    err_stream = build_audit_stream(_settings(audit_sink="stderr"))
    assert err_stream is not None and isinstance(err_stream.sink, StderrSink)
    with pytest.raises(ValueError, match="requires UNIFI_AUDIT_LOG"):
        _settings(audit_sink="file")
    for sink in ("none", "stderr"):
        with pytest.raises(ValueError, match="conflicts with UNIFI_AUDIT_LOG"):
            _settings(audit_sink=sink, audit_log=path)


@pytest.mark.parametrize(
    ("env", "value"),
    [
        ("UNIFI_AUDIT_SINK", "remote"),
        ("UNIFI_AUDIT_SINK", "syslog"),
        ("UNIFI_AUDIT_LEVEL", "trace"),
        ("UNIFI_AUDIT_LOG_MODE", "0644"),
        ("UNIFI_AUDIT_LOG_FORMAT", "xml"),
        ("UNIFI_AUDIT_CALLS", "sometimes"),
    ],
)
def test_invalid_values_fail_startup_naming_the_variable(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    with pytest.raises(ValueError, match=env):
        _settings()


def test_stderr_sink_writes_to_stderr_never_stdout(capsys):
    stream = build_audit_stream(_settings(audit_sink="stderr"))
    assert stream is not None
    stream.record(method="POST", path="/x", outcome="success", status=200)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["event"] == "audit"


def test_none_sink_is_disabled():
    stream = AuditStream(sink=NullSink())
    assert not stream.enabled
    stream.record(method="POST", path="/x", outcome="success", status=200)


# -------------------------------------------------------------------------- permissions
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize(("setting", "expected"), [("0600", 0o600), ("0640", 0o640)])
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_new_file_has_exactly_the_configured_mode(tmp_path, setting, expected, umask):
    path = tmp_path / "audit.jsonl"
    stream = build_audit_stream(_settings(audit_log=str(path), audit_log_mode=setting))
    assert stream is not None
    old = os.umask(umask)
    try:
        stream.record(method="POST", path="/x", outcome="success", status=200)
    finally:
        os.umask(old)
    mode = stat.S_IMODE(path.stat().st_mode)
    _artifact(
        "audit-permissions",
        {"case": "create", "setting": setting, "umask": f"{umask:04o}", "mode": f"{mode:04o}"},
    )
    assert mode == expected


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_existing_file_keeps_its_mode_and_startup_reports_it(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    path.chmod(0o644)
    stream = build_audit_stream(_settings(audit_log=str(path)))
    assert stream is not None
    stream.startup("0.0.0-test")
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    rec = json.loads(_lines(path)[0])
    _artifact("audit-permissions", {"case": "existing", "mode": rec["file_mode"]})
    assert rec["file_mode"] == "0644"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_symlink_to_a_regular_file_is_refused_fail_open(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(victim)
    stream = build_audit_stream(_settings(audit_log=str(link)))
    assert stream is not None
    stream.record(method="POST", path="/x", outcome="success", status=200)
    _artifact("audit-permissions", {"case": "symlink-regular", "refused": stream.unavailable})
    assert victim.read_text() == "keep\n"
    assert stream.unavailable


@pytest.mark.skipif(not os.path.exists(os.devnull), reason="needs a character device")
def test_symlink_to_this_process_stderr_is_followed(tmp_path, monkeypatch):
    link = tmp_path / "stderr-like"
    link.symlink_to(os.devnull)
    null_identity = audit._identity(os.stat(os.devnull))
    real = audit._fd_identity
    monkeypatch.setattr(audit, "_fd_identity", lambda fd: null_identity if fd == 2 else real(fd))
    stream = build_audit_stream(_settings(audit_log=str(link)))
    assert stream is not None
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert not stream.unavailable


@pytest.mark.skipif(not os.path.exists(os.devnull), reason="needs a character device")
def test_symlink_to_any_other_device_is_refused(tmp_path):
    link = tmp_path / "not-stderr"
    link.symlink_to(os.devnull)
    stream = build_audit_stream(_settings(audit_log=str(link)))
    assert stream is not None
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert stream.unavailable


# ------------------------------------------------------------------------ synthetic leak
@pytest.mark.parametrize("level", ["normal", "debug"])
@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("calls", [False, True])
def test_synthetic_secret_never_reaches_any_record(tmp_path, level, fmt, calls):
    stream, log = _stream(tmp_path, level=level, fmt=fmt, calls=calls)
    _every_event(stream)
    text = log.read_text(encoding="utf-8")
    _artifact(
        "audit-synthetic-leak",
        {
            "level": level,
            "format": fmt,
            "calls": calls,
            "records": len(text.splitlines()),
            "secret_found": SECRET in text,
            "unregistered_credential_found": UNREGISTERED_CREDENTIAL in text,
        },
    )
    assert text
    assert SECRET not in text
    assert UNREGISTERED_CREDENTIAL not in text
    assert "token=" not in text  # the query string is never recorded


def test_synthetic_secret_from_settings_is_scrubbed(tmp_path):
    path = tmp_path / "a.jsonl"
    key = "synthetic-settings-key-0c41d2"
    stream = build_audit_stream(Settings(api_key=key, audit_log=str(path), audit_level="debug"))
    assert stream is not None
    stream.record(method="POST", path=f"/x/{key}", outcome="success", status=200, body=[key])
    assert key not in path.read_text()


# ----------------------------------------------------------------- sink faults/recovery
@pytest.mark.parametrize("err", FAULT_ERRNOS, ids=[errno.errorcode[e] for e in FAULT_ERRNOS])
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_fault_fails_open_then_recovers(tmp_path, monkeypatch, err, fmt):
    stream, log = _stream(tmp_path, fmt=fmt)
    stream.record(method="POST", path="/before", outcome="success", status=200)
    real_open = os.open

    def failing_open(*args: Any, **kwargs: Any) -> int:
        raise OSError(err, os.strerror(err))

    monkeypatch.setattr(audit.os, "open", failing_open)
    for n in range(3):
        stream.record(method="POST", path=f"/lost/{n}", outcome="success", status=200)
    faulted = stream.unavailable
    monkeypatch.setattr(audit.os, "open", real_open)
    stream.record(method="POST", path="/after", outcome="success", status=200)
    lines = _lines(log)
    _artifact(
        "audit-sink-faults",
        {
            "errno": errno.errorcode[err],
            "format": fmt,
            "faulted": faulted,
            "recovered": not stream.unavailable,
            "lines": len(lines),
        },
    )
    assert faulted and not stream.unavailable
    assert len(lines) == 3
    assert "/lost/" not in "\n".join(lines)
    if fmt == "json":
        recovered = json.loads(lines[1])
        assert recovered["event"] == "audit.recovered"
        assert recovered == {**recovered, "lost_records": 3, "fault": errno.errorcode[err]}
    else:
        assert " event=audit.recovered lost_records=3 " in lines[1]


@pytest.mark.skipif(os.geteuid() == 0 if hasattr(os, "geteuid") else True, reason="root")
def test_real_eacces_and_enoent_fail_open_and_recover(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    stream = AuditStream(sink=FileSink(str(locked / "audit.jsonl")), fmt="json")
    try:
        stream.record(method="POST", path="/x", outcome="success", status=200)
        assert stream.unavailable
        locked.chmod(0o700)
        stream.record(method="POST", path="/y", outcome="success", status=200)
        assert not stream.unavailable
    finally:
        locked.chmod(0o700)
    missing = AuditStream(sink=FileSink(str(tmp_path / "no-such-dir" / "a.jsonl")), fmt="json")
    missing.record(method="POST", path="/x", outcome="success", status=200)
    assert missing.unavailable
    (tmp_path / "no-such-dir").mkdir()
    missing.record(method="POST", path="/y", outcome="success", status=200)
    assert not missing.unavailable
    _artifact("audit-sink-faults", {"errno": "EACCES+ENOENT(real)", "recovered": True})


def test_stderr_fault_fails_open():
    class Broken(io.StringIO):
        def write(self, s: str) -> int:
            raise OSError(errno.EPIPE, "broken pipe")

    stream = AuditStream(sink=StderrSink(stream=lambda: Broken()), fmt="json")
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert stream.unavailable


# --------------------------------------------------- isolation: a tool call never breaks
async def test_tool_call_succeeds_and_carries_the_notice_while_the_sink_fails(
    monkeypatch, tmp_path
):
    from tests import upstream_harness as uh
    from tests.test_cross_tool_invariants import _call

    env = {
        "UNIFI_AUDIT_LOG": str(tmp_path / "missing-dir" / "audit.jsonl"),
        "UNIFI_AUDIT_CALLS": "true",
    }
    res = await _call(monkeypatch, "list_hosts", uh.FakeUpstream(), args={}, env=env)
    meta = getattr(res, "meta", None) or {}
    _artifact("audit-sink-faults", {"errno": "ENOENT(tool-call)", "notice": meta})
    assert meta.get(NOTICE_META_KEY) == AUDIT_UNAVAILABLE
    (tmp_path / "missing-dir").mkdir()
    res = await _call(monkeypatch, "list_hosts", uh.FakeUpstream(), args={}, env=env)
    assert NOTICE_META_KEY not in (getattr(res, "meta", None) or {})
    recs = [json.loads(line) for line in _lines(tmp_path / "missing-dir" / "audit.jsonl")]
    # The harness builds a fresh client per call, so this stream starts healthy; the
    # recovery record of one long-lived stream is covered by the fault tests above.
    assert [r["event"] for r in recs] == ["call"]


# ------------------------------------------------- review hardening (security and code review)
UNREG = "unregistered-value-5d2e81"  # never registered: only field/query policy hides it


@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize(
    "path",
    [
        f"/v1/sites/x/../y?apiKey={UNREG}#{UNREG}",
        f"/v1/sites/x/../y#{UNREG}",
        f"tok?apiKey={UNREG}",
        f"?apiKey={UNREG}",
        f"/v1/sites/x/../y?t=a {UNREG}",
        f"/v1/sites/x/../y?t=it's{UNREG}",
        f"/v1/sites/x/../y%3fapiKey={UNREG}",
        f"/v1/sites/x/../y%23{UNREG}",
        f"/v1/sites/x/../y%253fapiKey={UNREG}",
    ],
)
async def test_unsafe_path_refusal_reason_never_carries_the_query(tmp_path, fmt, path):
    from unifi_fabric.client import UniFiClient

    log = tmp_path / "a.log"
    client = UniFiClient(
        Settings(api_key="synthetic-client-key", audit_log=str(log), audit_log_format=fmt)
    )
    with pytest.raises(ValueError, match="Unsafe API path"):
        await client.request("POST", path, json={})
    text = log.read_text()
    assert "refused" in text
    assert UNREG not in text and "apiKey" not in text


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_reason_cuts_quoted_queries_and_masks_echoed_inputs(tmp_path, fmt):
    stream, log = _stream(tmp_path, fmt=fmt)
    stream.record(
        method="POST",
        path="/x",
        outcome="refused",
        status=None,
        reason=(
            f"Unsafe API path 'https://h/x?token={UNREG}' and '/p/q?a=1#{UNREG}'; "
            f"1 validation error input_value={{'wifiPassword': '{UNREG}'}}, input_type=dict]"
        ),
    )
    text = log.read_text()
    assert UNREG not in text
    assert "input_value=***" in text


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_echoed_input_is_masked_whatever_it_contains(tmp_path, fmt):
    stream, log = _stream(tmp_path, fmt=fmt)
    for echoed in (
        f"{{'a': ['x'], 'wifiPassword': '{UNREG}'}}",
        f"{{'wifiPassword': '{UNREG}]z'}}",
        f"[1, ['{UNREG}']]",
        f"{{'note': ', input_type=str]', 'wifiPassword': '{UNREG}'}}",
    ):
        stream.record(
            method="POST",
            path="/x",
            outcome="refused",
            status=None,
            reason=f"1 validation error input_value={echoed}, input_type=dict]",
        )
    assert UNREG not in log.read_text()


def test_text_lines_escape_line_separators(tmp_path):
    stream, log = _stream(tmp_path, fmt="text", level="debug")
    stream.error("t", RuntimeError("a\u2028b\x85c"))
    stream.record(method="POST", path="/x", outcome="refused", status=None, reason="r\u2029")
    text = log.read_text(encoding="utf-8")
    assert "\u2028" not in text and "\x85" not in text and "\u2029" not in text
    assert len(text.splitlines()) == 2


def test_debug_masks_credential_shaped_keys_of_any_type(tmp_path):
    stream, log = _stream(tmp_path, level="debug")
    body = {
        "wifiPassword": UNREG,
        "simPin": 482913,
        "nested": [{"sharedKey": UNREG, "name": "ok"}],
        "nextToken": "cursor-stays",
    }
    stream.record(method="POST", path="/x", outcome="success", status=200, body=body)
    rec = json.loads(_lines(log)[0])
    assert UNREG not in _lines(log)[0] and "482913" not in _lines(log)[0]
    assert rec["body"]["nested"][0]["name"] == "ok"
    assert rec["body"]["nextToken"] == "cursor-stays"


def test_debug_value_cap_and_unserializable_placeholder(tmp_path):
    stream, log = _stream(tmp_path, level="debug")
    stream.record(method="POST", path="/x", outcome="success", status=200, body=["x" * 70000])
    stream.call("t", {"obj": object()})
    big, call = (json.loads(line) for line in _lines(log))
    assert big["body"]["truncated"] is True
    assert call["arguments"] == {"unserializable": "dict"}


@pytest.mark.parametrize("level", ["normal", "debug"])
def test_hostile_values_never_raise_into_the_caller(tmp_path, level):
    stream, log = _stream(tmp_path, level=level)
    deep: Any = []
    for _ in range(5000):
        deep = [deep]
    stream.record(method="POST", path="/\ud800", outcome="refused", status=None, reason="\ud800")
    stream.call("t", deep)
    stream.error("t", RuntimeError("\ud800 \x85"))
    for line in _lines(log):
        assert " " not in line and "\x85" not in line
        json.loads(line)


def test_closed_or_missing_stderr_fails_open():
    closed = io.StringIO()
    closed.close()
    for target in (lambda: closed, lambda: None):
        stream = AuditStream(sink=StderrSink(stream=target), fmt="json")  # type: ignore[arg-type]
        stream.record(method="POST", path="/x", outcome="success", status=200)
        assert stream.unavailable


def test_leak_sweep_on_the_stderr_sink():
    out = io.StringIO()
    stream = AuditStream(
        sink=StderrSink(stream=lambda: out),
        fmt="json",
        level="debug",
        calls=True,
        secrets=(SECRET,),
    )
    _every_event(stream)
    assert out.getvalue() and SECRET not in out.getvalue()
    assert UNREGISTERED_CREDENTIAL not in out.getvalue()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs")
def test_fifo_without_a_reader_is_a_fault_not_a_hang(tmp_path):
    fifo = tmp_path / "audit.fifo"
    os.mkfifo(fifo)
    stream = AuditStream(sink=FileSink(str(fifo)), fmt="json")
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert stream.unavailable


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_symlink_swapped_after_the_check_is_judged_on_the_descriptor(tmp_path, monkeypatch):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(os.devnull)
    real_open = os.open

    def swapping_open(path: Any, flags: int, *args: Any) -> int:
        if str(path) == str(link) and not flags & getattr(os, "O_NOFOLLOW", 0):
            return real_open(str(victim), flags, *args)  # the target changed under us
        return real_open(path, flags, *args)

    monkeypatch.setattr(audit.os, "open", swapping_open)
    stream = AuditStream(sink=FileSink(str(link)), fmt="json")
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert victim.read_text() == "keep\n"
    assert stream.unavailable


def test_the_stdout_descriptor_is_never_a_sink(tmp_path, monkeypatch):
    link = tmp_path / "stdout-like"
    link.symlink_to(os.devnull)
    null_identity = audit._identity(os.stat(os.devnull))
    real = audit._fd_identity
    monkeypatch.setattr(audit, "_fd_identity", lambda fd: null_identity if fd == 1 else real(fd))
    stream = AuditStream(sink=FileSink(str(link)), fmt="json")
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert stream.unavailable


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX owners")
def test_existing_file_of_another_owner_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    monkeypatch.setattr(audit.os, "geteuid", lambda: path.stat().st_uid + 1)
    stream = AuditStream(sink=FileSink(str(path)), fmt="json")
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert stream.unavailable and path.read_text() == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_existing_wider_file_warns_once_without_the_path(tmp_path, caplog):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    path.chmod(0o644)
    stream = AuditStream(sink=FileSink(str(path)), fmt="json")
    with caplog.at_level("WARNING", logger="unifi_fabric.audit"):
        for _ in range(3):
            stream.record(method="POST", path="/x", outcome="success", status=200)
    warnings = [r.getMessage() for r in caplog.records if "wider" in r.getMessage()]
    assert len(warnings) == 1 and str(path) not in warnings[0]


def test_probe_clears_the_notice_without_waiting_for_a_record(tmp_path, monkeypatch):
    stream, log = _stream(tmp_path)
    real_open = os.open
    monkeypatch.setattr(audit.os, "open", _raising(errno.ENOSPC))
    stream.record(method="POST", path="/lost", outcome="success", status=200)
    assert stream.probe() is True  # still failing: the notice stays
    monkeypatch.setattr(audit.os, "open", real_open)
    assert stream.probe() is False
    (rec,) = (json.loads(line) for line in _lines(log))
    assert rec["event"] == "audit.recovered" and rec["lost_records"] == 1


def test_losses_are_reported_once(tmp_path):
    results = iter([OSError(errno.EIO, "x"), None, OSError(errno.EIO, "x"), None, None])
    written: list[str] = []

    class Scripted:
        name = "file"

        def write(self, line: str) -> None:
            outcome = next(results)
            if outcome is not None:
                raise audit.SinkWriteError(outcome)
            written.append(line)

    stream = AuditStream(sink=Scripted(), fmt="json")  # type: ignore[arg-type]
    for n in range(3):
        stream.record(method="POST", path=f"/r{n}", outcome="success", status=200)
    lost = [json.loads(w)["lost_records"] for w in written if "audit.recovered" in w]
    assert lost == [1, 1]  # r0 lost, recovered(1); r1 lost after it, recovered(1) again


def test_a_cut_record_does_not_swallow_the_next_one(tmp_path, monkeypatch):
    stream, log = _stream(tmp_path)
    real_write = os.write
    calls = {"n": 0}

    def cutting_write(fd: int, data: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            return real_write(fd, bytes(data[:10]))  # a short write ...
        if calls["n"] == 2:
            raise OSError(errno.ENOSPC, "full")  # ... then the disk is full
        return real_write(fd, data)

    monkeypatch.setattr(audit.os, "write", cutting_write)
    stream.record(method="POST", path="/cut", outcome="success", status=200)
    stream.record(method="POST", path="/next", outcome="success", status=200)
    lines = _lines(log)
    assert len(lines) == 3  # the fragment, then the recovery record and the record
    assert json.loads(lines[1])["event"] == "audit.recovered"
    assert json.loads(lines[2])["path"] == "/next"


async def test_error_response_carries_the_notice_while_the_sink_fails(monkeypatch, tmp_path):
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh
    from tests.test_cross_tool_invariants import WRITE_TOOLS, _call

    env = {
        "UNIFI_AUDIT_LOG": str(tmp_path / "missing-dir" / "audit.jsonl"),
        "UNIFI_WRITE_POLICY": "deny",
    }
    with pytest.raises(ToolError, match=r"\[audit_unavailable\]"):
        await _call(monkeypatch, sorted(WRITE_TOOLS)[0], uh.FakeUpstream(), env=env)
