"""The opt-in audit hash chain, writer side.

Every key here is generated inside the test (``os.urandom``) or is a fixed test-only
constant; none is printed. The verifier side and the tamper matrix are in
``tests/test_audit_verify.py``; the byte-identical-when-off golden test is in
``tests/test_audit_chain_golden.py``.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import unifi_fabric.audit as audit
import unifi_fabric.audit_chain as audit_chain
from unifi_fabric import audit_verify
from unifi_fabric.audit import (
    CHAIN_EVENTS,
    EVENT_FIELDS,
    AuditStream,
    FileSink,
    audit_call,
    build_audit_stream,
    canonical_json,
)
from unifi_fabric.audit_chain import CHAIN_FIELDS, ZERO_MAC, ChainState, read_tail_link
from unifi_fabric.config import Settings
from unifi_fabric.secret_scrub import configured_secrets

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "unifi_fabric"
# Registered with the stream and scrubbed from every record; derived at run time so no
# secret-shaped literal sits in the source.
SECRET = "synthetic-chain-secret-" + hashlib.sha256(b"scrub-marker-chain").hexdigest()[:6]
POLICY_LINE = (
    '{"code":"invalid_policy_header","event":"policy.refusal",'
    '"request_id":"0123456789abcdef0123456789abcdef","schema_version":"1",'
    '"timestamp_utc":"2026-11-07T12:00:00.000002+00:00","tool_id":null,"upstream_calls":0}'
)


def key_text(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def chained(
    tmp_path: Path, key: bytes | None = None, *, level: str = "normal", name: str = "a.jsonl"
) -> tuple[AuditStream, Path, bytes]:
    key = key or os.urandom(32)
    log = tmp_path / name
    stream = AuditStream(
        sink=FileSink(str(log)),
        fmt="json",
        level=level,
        calls=True,
        secrets=(SECRET,),
        chain=ChainState.from_key(key, str(log)),
    )
    return stream, log, key


def ring(*keys: bytes) -> dict[str, bytes]:
    out = {}
    for key in keys:
        sub = audit_verify.subkey_of(key)
        out[audit_verify.kid_of(sub)] = sub
    return out


def verify(paths: list[Path], *keys: bytes, **kw: Any) -> audit_verify.Report:
    return audit_verify.verify([str(p) for p in paths], ring(*keys), **kw)


def raw_lines(log: Path) -> list[bytes]:
    return [line for line in log.read_bytes().split(b"\n") if line]


def independent_mac(key: bytes, line: bytes) -> tuple[str, str]:
    """(expected, recorded) MAC of one on-disk line, re-implemented here from the
    documented rule with hmac/hashlib: HMAC-SHA256(HMAC-SHA256(key, context),
    domain + line bytes without the ``,"mac":"..."`` member)."""
    recorded = re.search(rb',"mac":"([0-9a-f]{64})"', line)
    assert recorded is not None
    without = line.replace(recorded.group(0), b"", 1)
    subkey = hmac.new(key, b"unifi-fabric/audit-chain/v1", hashlib.sha256).digest()
    expected = hmac.new(
        subkey, b"unifi-fabric-audit-chain\x00v1\x00" + without, hashlib.sha256
    ).hexdigest()
    return expected, recorded.group(1).decode()


# ---------------------------------------------------------------- MAC known answers
#: HMAC-SHA256 of the fixed vector below, computed once with an independent script
#: (hashlib/hmac only) and pinned so a change of the MAC rule fails here.
PINNED_MAC = "39cd8dff621f02917ea76d62d81c0a0da7641a4671a7ebe0e7d8e79a90cbca96"
PINNED_KID = "45222830"


def test_fixed_known_answer_vector():
    """A pinned vector: a fixed test-only key, record and chain state."""
    key = bytes(range(32))
    state = ChainState(subkey=audit_chain.derive_subkey(key), chain_id="a" * 32)
    line, mac = state.seal(
        {"schema_version": "1", "event": "audit", "timestamp_utc": "t", "v": "café"},
        canonical_json,
    )
    assert line == (
        '{"chain":"'
        + "a" * 32
        + '","event":"audit","mac":"'
        + mac
        + '","prev":"'
        + ZERO_MAC
        + '","schema_version":"1","seq":0,"timestamp_utc":"t","v":"café"}'
    )
    assert independent_mac(key, line.encode())[0] == mac
    assert mac == PINNED_MAC
    assert audit_chain.key_id(audit_chain.derive_subkey(key)) == PINNED_KID
    assert audit_verify.kid_of(audit_verify.subkey_of(key)) == PINNED_KID
    assert audit_verify.mac_input(line.encode())[1] == PINNED_MAC


HOSTILE = {
    "lone_surrogate": "a\ud800b\udfffc",
    "c1_and_del": "x\x80\x85\x9f\x7fy",
    "line_separators": "p q r",
    "non_ascii": "café 中文 \U0001f600",
    "scrubbed_secret": f"before {SECRET} after",
    "quotes_and_escapes": 'q"\\\n\t\x00',
    "mac_lookalike": ',"mac":"' + "0" * 64 + '"',
}


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_mac_covers_the_exact_on_disk_bytes(tmp_path, case):
    """The MAC is over the bytes written (backslashreplace), and the
    verifier recovers that input from the raw line bytes."""
    stream, log, key = chained(tmp_path, level="debug")
    value = HOSTILE[case]
    with audit_call("chain_tool"):
        stream.record(
            method="POST",
            path=f"/p/{value}",
            outcome="refused",
            status=None,
            reason=value,
            body={"v": value, "ratio": 0.1 + 0.2, "big": 1e300, "n": -0.0},
        )
        stream.call("chain_tool", {"v": value, "f": 2.5})
        stream.error("chain_tool", ValueError(value))
    lines = raw_lines(log)
    assert len(lines) == 4  # chain_start + audit + call + error
    for line in lines:
        expected, recorded = independent_mac(key, line)
        assert expected == recorded
        cut, mac = audit_verify.mac_input(line)
        assert mac == recorded
        assert cut == line.replace(f',"mac":"{mac}"'.encode(), b"", 1)
        # The serialized record minus mac is exactly the MAC input bytes.
        rec = json.loads(line)
        rec.pop("mac")
        assert canonical_json(rec).encode("utf-8", errors="backslashreplace") == cut
    data = log.read_bytes()
    assert SECRET.encode() not in data
    if case == "lone_surrogate":
        assert b"\\ud800" in data  # backslashreplace bytes, covered by the MAC
    if case == "c1_and_del":
        assert b"\\u0085" in data and b"\\u007f" in data
    if case == "line_separators":
        assert b"\\u2028" in data and b"\\u2029" in data
    assert verify([log], key).findings == []


def test_float_values_are_covered_as_written(tmp_path):
    stream, log, key = chained(tmp_path, level="debug")
    stream.record(method="PUT", path="/f", outcome="success", status=200, body={"x": 0.1 + 0.2})
    line = raw_lines(log)[1]
    assert b"0.30000000000000004" in line
    assert independent_mac(key, line)[0] == json.loads(line)["mac"]
    tampered = log.read_bytes().replace(b"0.30000000000000004", b"0.3")
    log.write_bytes(tampered)
    assert [f.code for f in verify([log], key).findings] == ["BAD_MAC"]


def test_partial_newline_prefix_is_outside_the_mac(tmp_path, monkeypatch):
    """A record after a cut one starts with the ``_partial`` newline; the chain still
    verifies and the cut record is excused by the audit.recovered that follows."""
    stream, log, key = chained(tmp_path)
    stream.record(method="POST", path="/one", outcome="success", status=200)
    real_write = os.write
    calls = {"n": 0}

    def cut(fd: int, data: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            return real_write(fd, bytes(data)[:20])
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(audit.os, "write", cut)
    stream.record(method="POST", path="/cut", outcome="success", status=200)
    monkeypatch.setattr(audit.os, "write", real_write)
    assert stream.sink._partial  # noqa: SLF001 - the condition under test
    stream.record(method="POST", path="/after", outcome="success", status=200)
    data = log.read_bytes()
    assert b"\n\n" not in data and data.count(b"\n") == 5
    events = [json.loads(x)["event"] for x in raw_lines(log) if x.endswith(b"}")]
    assert events == ["audit.chain_start", "audit", "audit.recovered", "audit"]
    report = verify([log], key)
    assert report.findings == []
    assert [w.code for w in report.warnings] == ["MALFORMED_LINE_RECOVERED"]


# ------------------------------------------------------------- record shape / scrub
def test_chained_records_have_their_field_sets(tmp_path):
    stream, log, _key = chained(tmp_path, level="debug")
    stream.startup("0.0.0-test")
    stream.policy_record(POLICY_LINE)
    with audit_call("t"):
        stream.record(method="POST", path="/x", outcome="success", status=200, body={"a": 1})
        stream.call("t", {"a": 1})
        stream.error("t", RuntimeError("boom"))
    seen = []
    for raw in raw_lines(log):
        rec = json.loads(raw)
        seen.append(rec["event"])
        if rec["event"].startswith("policy."):
            assert raw.decode() == POLICY_LINE
            continue
        assert raw.decode() == canonical_json(rec), "not the canonical serialization"
        spec = EVENT_FIELDS[rec["event"]]
        assert set(spec["required"]) <= set(rec)
        assert set(rec) <= set(spec["required"]) | set(spec["optional"]) | set(CHAIN_FIELDS)
        assert set(CHAIN_FIELDS) <= set(rec)
    assert seen == [
        "audit.chain_start",
        "startup",
        "policy.refusal",
        "audit.seal",
        "audit",
        "call",
        "error",
    ]
    assert set(CHAIN_EVENTS) == {"audit.chain_start", "audit.seal"}


def test_chain_fields_are_added_after_scrubbing_and_never_scrubbed(tmp_path, monkeypatch):
    """A registered secret equal to the start of the chain id would be scrubbed if the
    chain fields went through the scrubber; they must not."""
    stream, log, key = chained(tmp_path)
    secret = stream.chain.chain_id[:16]
    stream.secrets = (SECRET, secret)
    stream.record(method="POST", path=f"/{secret}", outcome="success", status=200)
    recs = [json.loads(x) for x in raw_lines(log)]
    assert recs[1]["path"] == "/***"
    assert all(r["chain"] == stream.chain.chain_id for r in recs)
    assert verify([log], key).findings == []


def test_seq_and_prev_progress(tmp_path):
    stream, log, key = chained(tmp_path)
    for i in range(5):
        stream.record(method="POST", path=f"/{i}", outcome="success", status=200)
    recs = [json.loads(x) for x in raw_lines(log)]
    assert [r["seq"] for r in recs] == list(range(6))
    assert recs[0]["prev"] == ZERO_MAC
    for before, after in zip(recs, recs[1:], strict=False):
        assert after["prev"] == before["mac"]
    assert len({r["chain"] for r in recs}) == 1


def test_domain_separation(tmp_path):
    """Same record, different chain id / seq / prev / key: a different MAC."""
    key = os.urandom(32)
    rec = {"schema_version": "1", "event": "audit", "timestamp_utc": "t"}
    base = ChainState(subkey=audit_chain.derive_subkey(key), chain_id="b" * 32)
    macs = {base.seal(rec, canonical_json)[1]}
    for variant in (
        ChainState(subkey=base.subkey, chain_id="c" * 32),
        ChainState(subkey=base.subkey, chain_id="b" * 32, seq=1),
        ChainState(subkey=base.subkey, chain_id="b" * 32, prev="1" * 64),
        ChainState(subkey=audit_chain.derive_subkey(os.urandom(32)), chain_id="b" * 32),
    ):
        macs.add(variant.seal(rec, canonical_json)[1])
    assert len(macs) == 5
    # The raw key is never the MAC key, and the domain prefix is part of the input.
    data = canonical_json({**rec, "chain": "b" * 32, "seq": 0, "prev": ZERO_MAC}).encode()
    assert hmac.new(key, data, hashlib.sha256).hexdigest() not in macs
    assert hmac.new(base.subkey, data, hashlib.sha256).hexdigest() not in macs


# ------------------------------------------------------------------ seals (cond. 2)
@pytest.mark.parametrize("level", ["off", "normal", "debug"])
def test_every_policy_line_is_followed_by_its_seal_at_every_level(tmp_path, level):
    stream, log, key = chained(tmp_path, level=level)
    stream.startup("0.0.0-test")
    stream.policy_record(POLICY_LINE)
    stream.record(method="POST", path="/x", outcome="success", status=200)
    stream.policy_record(POLICY_LINE)
    lines = raw_lines(log)
    policy_at = [i for i, raw in enumerate(lines) if raw.decode() == POLICY_LINE]
    assert len(policy_at) == 2
    for i in policy_at:
        seal = json.loads(lines[i + 1])
        assert seal["event"] == "audit.seal"
        assert seal["sealed_sha256"] == hashlib.sha256(POLICY_LINE.encode()).hexdigest()
    if level == "off":
        events = [json.loads(x)["event"] for x in lines]
        assert events == [
            "audit.chain_start",
            "policy.refusal",
            "audit.seal",
            "policy.refusal",
            "audit.seal",
        ]
    assert verify([log], key).findings == []


def test_policy_line_and_seal_are_one_lock_acquisition(tmp_path):
    """Under concurrent writers a seal always directly follows its policy line."""
    stream, log, key = chained(tmp_path)
    barrier = threading.Barrier(8)

    def worker(n: int) -> None:
        barrier.wait()
        for i in range(40):
            if (i + n) % 3 == 0:
                stream.policy_record(POLICY_LINE)
            else:
                stream.record(method="POST", path=f"/{n}/{i}", outcome="success", status=200)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = raw_lines(log)
    for i, raw in enumerate(lines):
        if raw.decode() == POLICY_LINE:
            assert json.loads(lines[i + 1])["event"] == "audit.seal"
    assert verify([log], key).findings == []


def test_seal_lost_to_a_fault_is_excused_by_recovered(tmp_path, monkeypatch):
    stream, log, key = chained(tmp_path)
    stream.record(method="POST", path="/x", outcome="success", status=200)
    real_write = os.write
    calls = {"n": 0}

    def second_fails(fd: int, data: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 2:  # the seal after the policy line
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(audit.os, "write", second_fails)
    stream.policy_record(POLICY_LINE)
    monkeypatch.setattr(audit.os, "write", real_write)
    stream.record(method="POST", path="/y", outcome="success", status=200)
    report = verify([log], key)
    assert report.findings == []
    assert [w.code for w in report.warnings] == ["UNSEALED_POLICY_RECOVERED"]


# --------------------------------------------------------- fault / completeness (3c)
def test_enospc_then_recovery_keeps_the_chain(tmp_path, monkeypatch):
    stream, log, key = chained(tmp_path)
    stream.record(method="POST", path="/a", outcome="success", status=200)

    def enospc(fd: int, data: Any) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    real_write = os.write
    monkeypatch.setattr(audit.os, "write", enospc)
    for _ in range(3):
        stream.record(method="POST", path="/lost", outcome="success", status=200)
    assert stream.unavailable
    monkeypatch.setattr(audit.os, "write", real_write)
    stream.record(method="POST", path="/b", outcome="success", status=200)
    recs = [json.loads(x) for x in raw_lines(log)]
    assert [r["event"] for r in recs] == ["audit.chain_start", "audit", "audit.recovered", "audit"]
    assert recs[2]["lost_records"] == 3 and recs[2]["fault"] == "ENOSPC"
    assert [r["seq"] for r in recs] == [0, 1, 2, 3]
    assert verify([log], key).findings == []


def test_close_error_after_a_complete_line_advances_the_chain(tmp_path, monkeypatch):
    stream, log, key = chained(tmp_path)
    stream.record(method="POST", path="/a", outcome="success", status=200)
    real_close = os.close
    calls = {"n": 0}

    def close_fails_once(fd: int) -> None:
        real_close(fd)
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(audit.os, "close", close_fails_once)
    stream.record(method="POST", path="/closed-badly", outcome="success", status=200)
    monkeypatch.setattr(audit.os, "close", real_close)
    assert stream.sink.last_complete
    stream.record(method="POST", path="/b", outcome="success", status=200)
    recs = [json.loads(x) for x in raw_lines(log)]
    assert [r["seq"] for r in recs] == [0, 1, 2, 3, 4]
    assert [r["event"] for r in recs][2:4] == ["audit", "audit.recovered"]
    assert verify([log], key).findings == []


def test_a_record_missing_only_its_newline_is_complete(tmp_path, monkeypatch):
    """A short write that leaves only the newline unwritten, then a fault: the record
    is on disk whole, so the chain advances past it."""
    stream, log, key = chained(tmp_path)
    stream.record(method="POST", path="/a", outcome="success", status=200)
    real_write = os.write
    calls = {"n": 0}

    def all_but_newline(fd: int, data: Any) -> int:
        calls["n"] += 1
        data = bytes(data)
        if calls["n"] == 1:
            return real_write(fd, data[:-1])
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(audit.os, "write", all_but_newline)
    stream.record(method="POST", path="/no-newline", outcome="success", status=200)
    monkeypatch.setattr(audit.os, "write", real_write)
    assert stream.sink.last_complete
    stream.record(method="POST", path="/b", outcome="success", status=200)
    recs = [json.loads(x) for x in raw_lines(log)]
    assert [r["seq"] for r in recs] == [0, 1, 2, 3, 4]
    assert verify([log], key).findings == []


def test_sink_faults_never_raise_into_the_caller(tmp_path, monkeypatch):
    stream, _log, _key = chained(tmp_path)

    def boom(fd: int, data: Any) -> int:
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(audit.os, "write", boom)
    stream.startup("x")
    stream.policy_record(POLICY_LINE)
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert stream.probe() is True


# ------------------------------------------------------------ startup tail read (3b)
def test_restart_links_to_the_previous_chain(tmp_path):
    first, log, key = chained(tmp_path)
    for i in range(3):
        first.record(method="POST", path=f"/{i}", outcome="success", status=200)
    last = json.loads(raw_lines(log)[-1])
    second = AuditStream(
        sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log))
    )
    second.record(method="POST", path="/again", outcome="success", status=200)
    start = json.loads(raw_lines(log)[-2])
    assert start["event"] == "audit.chain_start"
    assert (start["prev_chain"], start["prev_seq"], start["prev_mac"]) == (
        last["chain"],
        last["seq"],
        last["mac"],
    )
    report = verify([log], key)
    assert report.findings == [] and report.warnings == []


def _no_read(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    reads: list[Any] = []

    def pread(*args: Any) -> bytes:
        reads.append(args)
        raise AssertionError("the tail must not be read")

    monkeypatch.setattr(audit_chain.os, "pread", pread)
    return reads


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX only")
def test_tail_read_never_touches_a_fifo(tmp_path, monkeypatch):
    fifo = tmp_path / "audit.fifo"
    os.mkfifo(fifo, 0o600)
    reads = _no_read(monkeypatch)
    assert read_tail_link(str(fifo)) is None
    assert reads == []
    state = ChainState.from_key(os.urandom(32), str(fifo))
    assert state.link is None
    assert state.start_fields()["prev_chain"] is None


@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="POSIX device")
def test_tail_read_never_touches_a_device(monkeypatch):
    reads = _no_read(monkeypatch)
    assert read_tail_link("/dev/null") is None
    assert reads == []


def test_tail_read_never_follows_a_symlink(tmp_path, monkeypatch):
    stream, log, key = chained(tmp_path)
    stream.record(method="POST", path="/x", outcome="success", status=200)
    link = tmp_path / "link.jsonl"
    link.symlink_to(log)
    reads = _no_read(monkeypatch)
    assert read_tail_link(str(link)) is None
    assert reads == []


def test_tail_read_skips_a_file_of_another_owner(tmp_path, monkeypatch):
    stream, log, _key = chained(tmp_path)
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert read_tail_link(str(log)) is not None
    reads = _no_read(monkeypatch)
    uid = os.geteuid()
    monkeypatch.setattr(audit_chain.os, "geteuid", lambda: uid + 1)
    assert read_tail_link(str(log)) is None
    assert reads == []


def test_tail_read_is_bounded_and_fails_open(tmp_path, monkeypatch):
    stream, log, _key = chained(tmp_path)
    stream.record(method="POST", path="/x", outcome="success", status=200)
    with log.open("ab") as fh:
        fh.write(b'{"event":"legacy"}\n' * 8000)  # > 64 KiB after the chained record
    assert read_tail_link(str(log)) is None  # outside the window: no link, no error
    stream.record(method="POST", path="/y", outcome="success", status=200)
    sizes: list[int] = []
    real = os.pread

    def pread(fd: int, n: int, off: int) -> bytes:
        sizes.append(n)
        return real(fd, n, off)

    monkeypatch.setattr(audit_chain.os, "pread", pread)
    link = read_tail_link(str(log))
    assert link is not None and link[1] == 2
    assert sizes == [audit_chain.TAIL_BYTES]
    assert read_tail_link(str(tmp_path / "missing")) is None


# ------------------------------------------------------------- settings (cond. 4/5)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **values: str) -> None:
    for name in (
        "UNIFI_AUDIT_CHAIN",
        "UNIFI_AUDIT_CHAIN_KEY",
        "UNIFI_AUDIT_HMAC_KEY",
        "UNIFI_AUDIT_SINK",
        "UNIFI_AUDIT_LOG",
        "UNIFI_AUDIT_LOG_FORMAT",
        "UNIFI_LOG_LEVEL",
        "UNIFI_TOOL_MODE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-chain-api-key")
    for name, value in values.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize(
    ("extra", "names"),
    [
        ({}, ["UNIFI_AUDIT_CHAIN_KEY"]),
        ({"UNIFI_AUDIT_CHAIN_KEY": "KEY", "UNIFI_AUDIT_LOG_FORMAT": "text"}, ["json"]),
        (
            {"UNIFI_AUDIT_CHAIN_KEY": "KEY", "UNIFI_AUDIT_SINK": "stderr", "UNIFI_AUDIT_LOG": ""},
            ["file sink"],
        ),
        ({"UNIFI_AUDIT_CHAIN_KEY": "KEY", "UNIFI_AUDIT_LOG": ""}, ["file sink"]),
        ({"UNIFI_AUDIT_CHAIN_KEY": "not-a-key"}, ["UNIFI_AUDIT_CHAIN_KEY"]),
        ({"UNIFI_AUDIT_CHAIN_KEY": "KEY=="}, ["UNIFI_AUDIT_CHAIN_KEY"]),
    ],
)
def test_chain_misconfiguration_fails_startup_naming_the_setting(
    monkeypatch, tmp_path, extra, names
):
    key = key_text(os.urandom(32))
    values = {"UNIFI_AUDIT_CHAIN": "true", "UNIFI_AUDIT_LOG": str(tmp_path / "a.jsonl")}
    values.update({k: v.replace("KEY", key) for k, v in extra.items()})
    _env(monkeypatch, tmp_path, **values)
    with pytest.raises((ValidationError, ValueError)) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_AUDIT_CHAIN" in text
    for name in names:
        assert name in text
    assert key not in text


def test_chain_key_equal_to_the_code_mode_key_is_refused(monkeypatch, tmp_path):
    key = key_text(os.urandom(32))
    _env(
        monkeypatch,
        tmp_path,
        UNIFI_AUDIT_CHAIN="true",
        UNIFI_AUDIT_LOG=str(tmp_path / "a.jsonl"),
        UNIFI_AUDIT_CHAIN_KEY=key,
        UNIFI_AUDIT_HMAC_KEY=key,
    )
    with pytest.raises(ValidationError) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_AUDIT_CHAIN_KEY" in text and "UNIFI_AUDIT_HMAC_KEY" in text
    assert key not in text
    # Refused with the chain off too: the two keys are never one.
    monkeypatch.setenv("UNIFI_AUDIT_CHAIN", "false")
    with pytest.raises(ValidationError):
        Settings()


def test_key_equality_uses_compare_digest(monkeypatch, tmp_path):
    import unifi_fabric.config as config

    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(config.hmac, "compare_digest", spy)
    _env(
        monkeypatch,
        tmp_path,
        UNIFI_AUDIT_CHAIN_KEY=key_text(os.urandom(32)),
        UNIFI_AUDIT_HMAC_KEY=key_text(os.urandom(32)),
    )
    Settings()
    assert len(calls) == 1


def test_valid_chain_settings_build_a_chained_stream(monkeypatch, tmp_path, caplog):
    key = os.urandom(32)
    log = tmp_path / "a.jsonl"
    _env(
        monkeypatch,
        tmp_path,
        UNIFI_AUDIT_CHAIN="true",
        UNIFI_AUDIT_LOG=str(log),
        UNIFI_AUDIT_CHAIN_KEY=key_text(key),
        UNIFI_AUDIT_HMAC_KEY=key_text(os.urandom(32)),
    )
    settings = Settings()
    assert settings.audit_chain_key_bytes() == key
    assert key_text(key) not in repr(settings)
    assert key_text(key) not in str(settings.model_dump())
    assert key_text(key) not in settings.model_dump_json()
    with caplog.at_level(logging.INFO, logger="unifi_fabric.audit"):
        stream = build_audit_stream(settings)
        assert stream is not None and stream.chain is not None
        stream.startup("0.0.0-test")
    assert any("audit chain head (chain start)" in r.getMessage() for r in caplog.records)
    assert not any("UNIFI_LOG_LEVEL" in r.getMessage() for r in caplog.records)
    assert verify([log], key).findings == []


def test_chain_key_is_a_configured_secret_and_is_scrubbed(monkeypatch, tmp_path, caplog):
    key = os.urandom(32)
    text = key_text(key)
    log = tmp_path / "a.jsonl"
    _env(
        monkeypatch,
        tmp_path,
        UNIFI_AUDIT_CHAIN="true",
        UNIFI_AUDIT_LOG=str(log),
        UNIFI_AUDIT_CHAIN_KEY=text,
        UNIFI_AUDIT_LEVEL="debug",
        UNIFI_AUDIT_CALLS="true",
    )
    settings = Settings()
    assert text in configured_secrets(settings)
    assert text in configured_secrets()  # from the environment alone
    stream = build_audit_stream(settings)
    assert stream is not None
    with caplog.at_level(logging.DEBUG):
        stream.startup("0.0.0-test")
        with audit_call("t"):
            stream.record(
                method="POST",
                path=f"/{text}?k={text}",
                outcome="refused",
                status=None,
                reason=f"echo {text} {json.dumps(text)} {text!r}",
                body={"note": text, "nested": [text]},
            )
            stream.call("t", {"note": text})
            stream.error("t", RuntimeError(text))
        stream.log_head("shutdown")
    data = log.read_bytes()
    assert text.encode() not in data
    assert key not in data and key.hex().encode() not in data
    assert b"***" in data
    for record in caplog.records:
        assert text not in record.getMessage()
    assert verify([log], key).findings == []


def test_key_set_while_chain_off_warns_and_has_no_effect(monkeypatch, tmp_path, caplog):
    log = tmp_path / "a.jsonl"
    _env(
        monkeypatch,
        tmp_path,
        UNIFI_AUDIT_LOG=str(log),
        UNIFI_AUDIT_CHAIN_KEY=key_text(os.urandom(32)),
    )
    with caplog.at_level(logging.WARNING, logger="unifi_fabric.audit"):
        stream = build_audit_stream(Settings())
    assert stream is not None and stream.chain is None
    assert any(
        "UNIFI_AUDIT_CHAIN_KEY is set but UNIFI_AUDIT_CHAIN is off" in r.getMessage()
        for r in caplog.records
    )
    stream.record(method="POST", path="/x", outcome="success", status=200)
    assert not any(f in json.loads(raw_lines(log)[0]) for f in CHAIN_FIELDS)


@pytest.mark.parametrize("level", ["WARNING", "ERROR", "CRITICAL"])
def test_log_level_above_info_warns_once_that_anchors_are_hidden(
    monkeypatch, tmp_path, caplog, level
):
    _env(
        monkeypatch,
        tmp_path,
        UNIFI_AUDIT_CHAIN="true",
        UNIFI_AUDIT_LOG=str(tmp_path / "a.jsonl"),
        UNIFI_AUDIT_CHAIN_KEY=key_text(os.urandom(32)),
        UNIFI_LOG_LEVEL=level,
    )
    with caplog.at_level(logging.DEBUG, logger="unifi_fabric.audit"):
        build_audit_stream(Settings())
    hits = [r for r in caplog.records if "UNIFI_LOG_LEVEL is above INFO" in r.getMessage()]
    assert len(hits) == 1
    assert hits[0].levelno >= max(logging.WARNING, logging.getLevelName(level))


def test_head_is_logged_at_start_every_100_records_and_at_shutdown(tmp_path, caplog):
    stream, log, _key = chained(tmp_path)
    with caplog.at_level(logging.INFO, logger="unifi_fabric.audit"):
        for i in range(200):
            stream.record(method="POST", path=f"/{i}", outcome="success", status=200)
        stream.log_head("shutdown")
    heads = [r for r in caplog.records if "audit chain head" in r.getMessage()]
    assert all(r.levelno == logging.INFO for r in heads)
    seqs = [int(r.getMessage().rsplit(":", 2)[1]) for r in heads]
    assert seqs == [0, 100, 200, 200]
    last = json.loads(raw_lines(log)[-1])
    assert heads[-1].getMessage().endswith(f"{last['chain']}:{last['seq']}:{last['mac']}")


def test_chain_needs_json_and_the_file_sink():
    state = ChainState.from_key(os.urandom(32), None)
    with pytest.raises(ValueError, match="UNIFI_AUDIT_CHAIN"):
        AuditStream(sink=FileSink("/nonexistent/x"), fmt="text", chain=state)
    with pytest.raises(ValueError, match="UNIFI_AUDIT_CHAIN"):
        AuditStream(sink=audit.StderrSink(), fmt="json", chain=state)


def test_chain_state_repr_holds_no_key_material():
    key = os.urandom(32)
    state = ChainState.from_key(key, None)
    text = repr(state) + repr(AuditStream(sink=FileSink("/nonexistent/x"), chain=state))
    assert key.hex() not in text and state.subkey.hex() not in text
    assert repr(state.subkey) not in text


# ------------------------------------------------- the verifier is not server code
def test_the_verifier_imports_no_server_code():
    code = (
        "import sys, unifi_fabric.audit_verify\n"
        "print(sorted(m for m in sys.modules if m.startswith('unifi_fabric') "
        "or m.split('.')[0] in ('fastmcp', 'pydantic', 'pydantic_settings', 'httpx', 'mcp')))"
    )
    out = subprocess.check_output([sys.executable, "-c", code], text=True)  # noqa: S603
    assert out.strip() == "['unifi_fabric', 'unifi_fabric.audit_verify']"


def test_no_server_module_imports_the_verifier():
    import ast

    for path in SRC.rglob("*.py"):
        if path.name == "audit_verify.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or "", *(a.name for a in node.names)]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                names = [node.value] if node.value.endswith("audit_verify") else []
            else:
                continue
            assert not any(n.endswith("audit_verify") for n in names), path


@pytest.mark.asyncio
async def test_the_verifier_is_never_an_mcp_tool():
    from unifi_fabric.server import mcp

    tools = await mcp.list_tools(run_middleware=False)
    assert tools
    for tool in tools:
        name = tool.name.lower()
        assert not ("audit" in name and ("verify" in name or "chain" in name)), tool.name
        fn = getattr(tool, "fn", None)
        assert getattr(fn, "__module__", "") != "unifi_fabric.audit_verify", tool.name


def test_a_restart_after_a_cut_last_line_starts_on_its_own_line(tmp_path):
    """A crash can leave the last record without its newline. The next process must not
    append its audit.chain_start onto that line (one extra CHAIN_PREFIX_MISSING)."""
    first, log, key = chained(tmp_path)
    first.record(method="POST", path="/one", outcome="success", status=200)
    cut = raw_lines(log)[-1][:20]
    log.write_bytes(b"".join(x + b"\n" for x in raw_lines(log)[:-1]) + cut)
    second = AuditStream(
        sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log))
    )
    second.record(method="POST", path="/again", outcome="success", status=200)
    lines = raw_lines(log)
    assert cut in lines  # the cut record stays alone on its line
    assert b"audit.chain_start" in lines[-2] and lines[-2].startswith(b'{"')
    codes = [f.code for f in verify([log], key).findings]
    assert "CHAIN_PREFIX_MISSING" not in codes
