"""``unifi-fabric-audit-verify`` and the tamper matrix.

Each tamper case edits a chained file the way an actor without the key could and pins the
finding the verifier must report. The two cases the chain cannot see on its own (a cut
tail and a whole file rolled back to an older copy) are pinned both ways: clean without
an anchor, caught with ``--expect-head``. Keys are generated in the test and never
printed; every CLI test also asserts no key, key path or key digest reaches the output.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.test_audit_chain import POLICY_LINE, chained, key_text, raw_lines, ring, verify
from unifi_fabric import audit, audit_verify
from unifi_fabric.audit import AuditStream, FileSink
from unifi_fabric.audit_chain import ChainState


def build(tmp_path: Path, n: int = 6, key: bytes | None = None) -> tuple[Path, bytes]:
    """A chained file: chain_start, startup, a policy line + seal, then n audit records."""
    stream, log, key = chained(tmp_path, key)
    stream.startup("0.0.0-test")
    stream.policy_record(POLICY_LINE)
    for i in range(n):
        stream.record(method="POST", path=f"/r/{i}", outcome="success", status=200)
    return log, key


def write_lines(log: Path, lines: list[bytes]) -> None:
    log.write_bytes(b"".join(line + b"\n" for line in lines))


def codes(report: audit_verify.Report) -> list[str]:
    return [f.code for f in report.findings]


def index_of(lines: list[bytes], event: str) -> int:
    return next(i for i, x in enumerate(lines) if json.loads(x).get("event") == event)


# ------------------------------------------------------------------- tamper matrix
def test_untouched_file_is_clean(tmp_path):
    log, key = build(tmp_path)
    report = verify([log], key)
    assert report.findings == [] and report.warnings == []
    assert report.exit_code == 0


def test_edit_a_field(tmp_path):
    log, key = build(tmp_path)
    log.write_bytes(log.read_bytes().replace(b'"/r/2"', b'"/r/X"'))
    assert codes(verify([log], key)) == ["BAD_MAC"]


def test_edit_the_mac(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    rec = json.loads(lines[5])
    lines[5] = lines[5].replace(rec["mac"].encode(), b"f" * 64)
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["BAD_MAC", "PREV_MISMATCH"]


def test_delete_the_first_record(tmp_path):
    log, key = build(tmp_path)
    write_lines(log, raw_lines(log)[1:])
    report = verify([log], key)
    assert codes(report) == ["CHAIN_PREFIX_MISSING"]
    assert report.exit_code == 1


@pytest.mark.parametrize("which", ["middle", "last_but_one"])
def test_delete_a_record(tmp_path, which):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    del lines[5 if which == "middle" else len(lines) - 2]
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["SEQ_GAP"]


def test_insert_a_copied_record(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    lines.insert(7, lines[4])
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["DUP_SEQ"]


def test_swap_two_records(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    lines[5], lines[6] = lines[6], lines[5]
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["SEQ_GAP", "DUP_SEQ"]


def test_duplicate_a_record(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    lines.insert(6, lines[5])
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["DUP_SEQ"]


def test_truncated_tail_needs_an_anchor(tmp_path):
    """Undetectable without an anchor (documented limit 1); caught with one."""
    log, key = build(tmp_path)
    head = verify([log], key).heads()
    assert len(head) == 1
    lines = raw_lines(log)
    write_lines(log, lines[:-2])
    assert verify([log], key).findings == []
    chain, seq, mac = head[0].split(":")
    anchored = verify([log], key, expect_heads=[(chain, int(seq), mac)])
    assert codes(anchored) == ["ANCHOR_MISSING"]


def test_older_copy_needs_an_anchor(tmp_path):
    """A whole file rolled back to an older valid copy (documented limit 2)."""
    log, key = build(tmp_path, n=2)
    older = log.read_bytes()
    stream = AuditStream(
        sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log))
    )
    stream.record(method="DELETE", path="/later", outcome="success", status=200)
    anchor = verify([log], key).heads()
    log.write_bytes(older)
    assert verify([log], key).findings == []
    anchors = [(c, int(s), m) for c, s, m in (h.split(":") for h in anchor)]
    assert "ANCHOR_MISSING" in codes(verify([log], key, expect_heads=anchors))


def test_anchor_mismatch(tmp_path):
    log, key = build(tmp_path)
    chain, seq, _mac = verify([log], key).heads()[0].split(":")
    report = verify([log], key, expect_heads=[(chain, int(seq), "0" * 64)])
    assert codes(report) == ["ANCHOR_MISMATCH"]


def test_remove_the_seal_after_a_policy_line(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    del lines[index_of(lines, "audit.seal")]
    write_lines(log, lines)
    assert sorted(codes(verify([log], key))) == ["MISSING_SEAL", "SEQ_GAP"]


def test_delete_only_the_policy_line(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    del lines[index_of(lines, "policy.refusal")]
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["ORPHAN_SEAL"]


@pytest.mark.parametrize("where", ["before_seal", "after_seal", "end"])
def test_duplicate_a_policy_line(tmp_path, where):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    i = index_of(lines, "policy.refusal")
    at = {"before_seal": i + 1, "after_seal": i + 2, "end": len(lines)}[where]
    lines.insert(at, lines[i])
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["MISSING_SEAL"]


def test_inject_an_unchained_line(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    lines.insert(
        6,
        b'{"event":"audit","method":"POST","outcome":"success","path":"/forged",'
        b'"schema_version":"1","status":200,"timestamp_utc":"2026-11-07T00:00:00+00:00"}',
    )
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["UNCHAINED_LINE"]


def test_inject_a_malformed_line(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    lines.insert(6, b'{"event":"audit","path":"/forg')
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["MALFORMED_LINE"]


def test_forged_chain_with_another_key(tmp_path):
    """Someone without the key rewrites a record under their own key, keeping the kid."""
    log, key = build(tmp_path)
    forged_dir = tmp_path / "forged"
    forged_dir.mkdir()
    other, _ = build(forged_dir)
    lines = raw_lines(log)
    lines[6] = raw_lines(other)[6]
    write_lines(log, lines)
    found = codes(verify([log], key))
    assert "BAD_MAC" in found


def test_wrong_key_is_an_unknown_kid(tmp_path):
    log, _key = build(tmp_path)
    report = verify([log], os.urandom(32))
    assert codes(report) == ["UNKNOWN_KID"]


def test_splice_a_record_from_another_chain(tmp_path):
    key = os.urandom(32)
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    log_a, _ = build(a_dir, key=key)
    log_b, _ = build(b_dir, key=key)
    a, b = raw_lines(log_a), raw_lines(log_b)
    chain_a, chain_b = json.loads(a[0])["chain"], json.loads(b[0])["chain"]
    a[6] = b[6].replace(chain_b.encode(), chain_a.encode())
    write_lines(log_a, a)
    assert "BAD_MAC" in codes(verify([log_a], key))


def test_two_interleaved_chains_stay_valid(tmp_path):
    key = os.urandom(32)
    one, log, _ = chained(tmp_path, key)
    two = AuditStream(sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log)))
    for i in range(10):
        (one if i % 2 else two).record(method="POST", path=f"/{i}", outcome="success", status=200)
        if i == 4:
            one.policy_record(POLICY_LINE)
            two.policy_record(POLICY_LINE)
    report = verify([log], key)
    assert report.findings == []
    assert len(report.chains) == 2
    # The second chain read no link (the file was empty when it was built).
    assert [w.code for w in report.warnings] == ["UNLINKED_CHAIN_START"]


def test_deleting_a_whole_earlier_chain_is_a_missing_prefix(tmp_path):
    """Prefix deletion never passes silently."""
    log, key = build(tmp_path)
    first_len = len(raw_lines(log))
    second = AuditStream(
        sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log))
    )
    second.record(method="POST", path="/second", outcome="success", status=200)
    assert verify([log], key).findings == []
    write_lines(log, raw_lines(log)[first_len:])
    report = verify([log], key)
    assert codes(report) == ["CHAIN_PREFIX_MISSING"]
    allowed = verify([log], key, allow_rotated_prefix=True)
    assert allowed.findings == []
    assert [w.code for w in allowed.warnings] == ["CHAIN_PREFIX_MISSING_ALLOWED"]


def test_rotation_across_two_files(tmp_path):
    """``create``-style rotation: the chain continues in the new file."""
    stream, log, key = chained(tmp_path)
    for i in range(3):
        stream.record(method="POST", path=f"/{i}", outcome="success", status=200)
    rotated = tmp_path / "a.jsonl.1"
    log.rename(rotated)
    for i in range(3):
        stream.record(method="POST", path=f"/new/{i}", outcome="success", status=200)
    assert json.loads(raw_lines(log)[0])["seq"] == 4
    assert verify([rotated, log], key).findings == []
    assert codes(verify([log], key)) == ["CHAIN_PREFIX_MISSING"]
    assert codes(verify([log, rotated], key)) != []  # wrong order is not clean
    lone = verify([log], key, allow_rotated_prefix=True)
    assert lone.findings == [] and len(lone.warnings) == 1


def test_copytruncate_loss_shows_as_a_seq_gap(tmp_path):
    stream, log, key = chained(tmp_path)
    for i in range(4):
        stream.record(method="POST", path=f"/{i}", outcome="success", status=200)
    copy = tmp_path / "a.jsonl.1"
    lines = raw_lines(log)
    write_lines(copy, lines[:3])  # the copy missed the last two lines
    log.write_bytes(b"")  # truncate
    stream.record(method="POST", path="/after", outcome="success", status=200)
    assert codes(verify([copy, log], key)) == ["SEQ_GAP"]


def test_legacy_lines_before_the_chain_are_counted_not_flagged(tmp_path):
    log = tmp_path / "a.jsonl"
    legacy = AuditStream(sink=FileSink(str(log)), fmt="json")
    legacy.record(method="POST", path="/old", outcome="success", status=200)
    legacy.policy_record(POLICY_LINE)
    key = os.urandom(32)
    stream = AuditStream(
        sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log))
    )
    stream.record(method="POST", path="/new", outcome="success", status=200)
    report = verify([log], key)
    assert report.findings == [] and report.legacy_lines == 2
    # A writer without the chain after it began is a finding.
    legacy.record(method="POST", path="/mixed", outcome="success", status=200)
    assert codes(verify([log], key)) == ["UNCHAINED_LINE"]


def test_link_target_changed(tmp_path):
    log, key = build(tmp_path)
    second = AuditStream(
        sink=FileSink(str(log)), fmt="json", chain=ChainState.from_key(key, str(log))
    )
    second.record(method="POST", path="/second", outcome="success", status=200)
    lines = raw_lines(log)
    target = len(lines) - 3  # the record the second chain links to
    lines[target] = lines[target].replace(b'"/r/5"', b'"/r/Z"')
    write_lines(log, lines)
    assert codes(verify([log], key)) == ["BAD_MAC"]


def test_a_cut_final_line_is_a_cut_tail_warning(tmp_path):
    log, key = build(tmp_path)
    data = log.read_bytes()
    log.write_bytes(data[:-30])
    report = verify([log], key)
    assert report.findings == []
    assert [w.code for w in report.warnings] == ["TRUNCATED_TAIL"]


def test_escaped_or_duplicated_mac_key_is_rejected(tmp_path):
    log, key = build(tmp_path)
    lines = raw_lines(log)
    lines[5] = lines[5].replace(b'"mac":', b'"m\\u0061c":', 1)
    write_lines(log, lines)
    assert "BAD_MAC" in codes(verify([log], key))
    other = tmp_path / "dup"
    other.mkdir()
    log2, key2 = build(other)
    lines = raw_lines(log2)
    lines[5] = lines[5][:-1] + b',"mac":"' + b"0" * 64 + b'"}'
    write_lines(log2, lines)
    assert "BAD_MAC" in codes(verify([log2], key2))


@pytest.mark.parametrize(
    ("data", "ok"),
    [
        (b"{}", True),
        (b'{"a":1}', True),
        (b'{"a":{"b":[1,{"c":"}"}]},"mac":"x"}', True),
        (b'{"a":1,}', False),
        (b"[1]", False),
        (b'{"a":"\\"}', False),
    ],
)
def test_member_scanner_shapes(data, ok):
    assert (audit_verify.top_level_members(data) is not None) is ok


def test_nested_mac_fields_are_not_the_record_mac(tmp_path):
    stream, log, key = chained(tmp_path, level="debug")
    stream.record(
        method="POST",
        path="/n",
        outcome="success",
        status=200,
        body={"mac": "0" * 64, "x": {"mac": "1" * 64}},
    )
    assert verify([log], key).findings == []


# ---------------------------------------------------------------------- CLI / keys
def keyfile(tmp_path: Path, *keys: bytes, mode: int = 0o600, name: str = "ring") -> Path:
    path = tmp_path / name
    body = "# test keyring\n\n" + "".join(key_text(k) + "\n" for k in keys)
    path.write_text(body, encoding="ascii")
    path.chmod(mode)
    return path


def run_cli(*args: str, env_key: bytes | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "UNIFI_AUDIT_CHAIN_KEY"}
    if env_key is not None:
        env["UNIFI_AUDIT_CHAIN_KEY"] = key_text(env_key)
    return subprocess.run(  # noqa: S603 - the module under test
        [sys.executable, "-m", "unifi_fabric.audit_verify", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def assert_no_key_material(
    result: subprocess.CompletedProcess[str], *keys: bytes, paths: tuple[Path, ...] = ()
) -> None:
    out = result.stdout + result.stderr
    for key in keys:
        sub = audit_verify.subkey_of(key)
        for form in (
            key_text(key),
            base64.b64encode(key).decode(),
            key.hex(),
            sub.hex(),
            hashlib.sha256(key).hexdigest(),
            hashlib.sha256(key_text(key).encode()).hexdigest(),
        ):
            assert form not in out
    for path in paths:
        assert str(path) not in out and path.name not in out


def test_cli_exit_codes_and_key_file(tmp_path):
    log, key = build(tmp_path)
    ring_file = keyfile(tmp_path, os.urandom(32), key)
    clean = run_cli("--key-file", str(ring_file), "--print-head", str(log))
    assert clean.returncode == 0, clean.stderr
    assert "RESULT NO TAMPER EVIDENCE" in clean.stdout and "HEAD " in clean.stdout
    kid = audit_verify.kid_of(audit_verify.subkey_of(key))
    assert f"kid={kid}" in clean.stdout  # the kid is the only key-derived value shown
    assert_no_key_material(clean, key, paths=(ring_file,))
    log.write_bytes(log.read_bytes().replace(b'"/r/1"', b'"/r/9"'))
    tampered = run_cli("--key-file", str(ring_file), str(log))
    assert tampered.returncode == 1
    assert "FINDING BAD_MAC" in tampered.stdout
    assert_no_key_material(tampered, key, paths=(ring_file,))


def test_cli_key_from_the_environment(tmp_path):
    log, key = build(tmp_path)
    result = run_cli(str(log), env_key=key)
    assert result.returncode == 0, result.stderr
    assert_no_key_material(result, key)
    assert run_cli(str(log)).returncode == 2  # no key at all


@pytest.mark.parametrize("flag", ["--key", "--chain-key", "-k", "--key-fil"])
def test_cli_has_no_key_argument_and_never_echoes_arguments(tmp_path, flag):
    log, key = build(tmp_path)
    result = run_cli(flag, key_text(key), str(log), env_key=key)
    assert result.returncode == 2
    assert_no_key_material(result, key)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620, 0o602, 0o660])
def test_key_file_with_group_or_other_bits_is_refused(tmp_path, mode):
    log, key = build(tmp_path)
    ring_file = keyfile(tmp_path, key, mode=mode)
    result = run_cli("--key-file", str(ring_file), str(log))
    assert result.returncode == 2
    assert "key file refused" in result.stderr
    assert_no_key_material(result, key, paths=(ring_file,))


def test_key_file_0400_is_accepted(tmp_path):
    log, key = build(tmp_path)
    assert run_cli("--key-file", str(keyfile(tmp_path, key, mode=0o400)), str(log)).returncode == 0


def test_key_file_symlink_is_refused(tmp_path):
    log, key = build(tmp_path)
    target = keyfile(tmp_path, key)
    link = tmp_path / "ring-link"
    link.symlink_to(target)
    result = run_cli("--key-file", str(link), str(log))
    assert result.returncode == 2
    assert_no_key_material(result, key, paths=(link, target))


def test_key_file_of_another_owner_or_not_a_file_is_refused(tmp_path, monkeypatch):
    _log, key = build(tmp_path)
    ring_file = keyfile(tmp_path, key)
    uid = os.geteuid()
    monkeypatch.setattr(audit_verify.os, "geteuid", lambda: uid + 1)
    with pytest.raises(audit_verify.UsageError, match="key file refused"):
        audit_verify.read_key_file(str(ring_file))
    monkeypatch.undo()
    with pytest.raises(audit_verify.UsageError, match="key file refused"):
        audit_verify.read_key_file(str(tmp_path))


def test_keyring_errors_give_the_line_number_only(tmp_path):
    log, key = build(tmp_path)
    bad = "Zm9v" + key_text(key)[4:-2]
    ring_file = tmp_path / "ring"
    ring_file.write_text(f"{key_text(key)}\n# comment\n{bad}\n", encoding="ascii")
    ring_file.chmod(0o600)
    result = run_cli("--key-file", str(ring_file), str(log))
    assert result.returncode == 2
    assert "key file line 3:" in result.stderr
    assert bad not in result.stderr + result.stdout
    assert_no_key_material(result, key, paths=(ring_file,))


def test_bad_environment_key_is_a_usage_error(tmp_path):
    log, _key = build(tmp_path)
    env = {k: v for k, v in os.environ.items() if k != "UNIFI_AUDIT_CHAIN_KEY"}
    env["UNIFI_AUDIT_CHAIN_KEY"] = "not-a-valid-key-value"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "unifi_fabric.audit_verify", str(log)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 2
    assert "not-a-valid-key-value" not in result.stdout + result.stderr


def test_cli_anchor_and_allow_rotated_prefix(tmp_path):
    log, key = build(tmp_path)
    ring_file = keyfile(tmp_path, key)
    head = run_cli("--key-file", str(ring_file), "--print-head", str(log)).stdout
    anchor = next(x for x in head.splitlines() if x.startswith("HEAD ")).split()[1]
    write_lines(log, raw_lines(log)[1:-1])
    missing = run_cli("--key-file", str(ring_file), "--expect-head", anchor, str(log))
    assert missing.returncode == 1
    assert "ANCHOR_MISSING" in missing.stdout and "CHAIN_PREFIX_MISSING" in missing.stdout
    allowed = run_cli("--key-file", str(ring_file), "--allow-rotated-prefix", str(log))
    assert allowed.returncode == 0
    assert "INFO CHAIN_PREFIX_MISSING allowed by --allow-rotated-prefix: 1" in allowed.stdout
    bad_anchor = run_cli("--key-file", str(ring_file), "--expect-head", "x:y", str(log))
    assert bad_anchor.returncode == 2


def test_cli_json_report(tmp_path):
    log, key = build(tmp_path)
    result = run_cli("--json", str(log), env_key=key)
    doc: dict[str, Any] = json.loads(result.stdout)
    assert result.returncode == 0
    assert doc["result"] == "no_tamper_evidence" and doc["exit"] == 0
    assert set(doc) == {
        "result",
        "exit",
        "findings",
        "warnings",
        "legacy_lines",
        "chained_records",
        "chains",
        "heads",
        "allowed_rotated_prefix",
    }
    assert doc["chained_records"] == len(raw_lines(log)) - 1  # the policy line is unchained
    assert_no_key_material(result, key)


def test_console_script_is_declared_and_runs():
    import importlib.metadata

    entries = importlib.metadata.distribution("unifi-fabric-mcp-server").entry_points
    scripts = {ep.name: ep.value for ep in entries if ep.group == "console_scripts"}
    assert scripts["unifi-fabric-audit-verify"] == "unifi_fabric.audit_verify:cli"
    exe = Path(sys.executable).parent / "unifi-fabric-audit-verify"
    result = subprocess.run([str(exe), "--help"], capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0 and "tamper" in result.stdout.lower()


def test_ring_helper_matches_the_cli_keyring(tmp_path):
    key = os.urandom(32)
    path = keyfile(tmp_path, key)
    loaded = audit_verify.load_keys([str(path)], environ={})
    assert loaded == ring(key)


# ------------------------------------------------- forged lines before a genuine recovery
def _log_with_one_lost_seal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, bytes]:
    """A genuine fault: the seal after a policy line is lost (one record lost), then a
    recovered record. The verifier excuses exactly that one unsealed policy line."""
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
    return log, key


def test_a_genuine_fault_is_still_excused_by_its_recovered_record(tmp_path, monkeypatch):
    log, key = _log_with_one_lost_seal(tmp_path, monkeypatch)
    report = verify([log], key)
    assert report.findings == []
    assert [w.code for w in report.warnings] == ["UNSEALED_POLICY_RECOVERED"]


def test_forged_lines_before_a_genuine_recovery_are_findings(tmp_path, monkeypatch):
    log, key = _log_with_one_lost_seal(tmp_path, monkeypatch)
    lines = raw_lines(log)
    at = index_of(lines, "audit.recovered")
    assert json.loads(lines[at])["lost_records"] == 1
    # A forged complete policy line and a garbage line, placed before the genuine record.
    forged = [POLICY_LINE.encode(), b'{"event":"audit","tool":"forged"']
    write_lines(log, [*lines[:at], *forged, *lines[at:]])
    report = verify([log], key)
    # One record was lost, so one line is excused; the other two are not accounted for.
    assert sorted(codes(report)) == ["MALFORMED_LINE", "MISSING_SEAL"]
    assert report.exit_code == 1
