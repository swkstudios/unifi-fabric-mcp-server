"""Verify the tamper-evident audit hash chain (``UNIFI_AUDIT_CHAIN``).

Usage::

    unifi-fabric-audit-verify [--key-file PATH]... [--expect-head CHAIN:SEQ:MAC]...
        [--allow-rotated-prefix] [--print-head] [--json] FILE [FILE...]
    python -m unifi_fabric.audit_verify ...

Files are given oldest first (a rotated ``audit.log.1`` before ``audit.log``).

Keys never come from the command line. They come from ``UNIFI_AUDIT_CHAIN_KEY`` and/or
one or more key files: a key file is opened without following a symlink and must be a
regular file owned by the invoking user with no group or other permission bits (0600 or
0400); it holds one key per line (canonical unpadded base64url of 32 bytes; blank lines
and ``#`` comments are ignored). A key error names the line number only. The only
key-derived value ever printed is a ``kid`` (a keyed 32-bit fingerprint).

Exit status: 0 no tamper evidence, 1 tamper evidence (one finding or more), 2 usage or
key error.

What this proves, and what it does not: the chain is tamper-evident, not tamper-proof.
Without an anchor held elsewhere (``--expect-head``) it cannot see a cut tail or a whole
file replaced by an older copy, and anyone holding the key can write a valid chain. See
docs/CONFIGURATION.md, "Tamper evidence".

This module is an independent implementation of the chain rules: it imports nothing from
the server (stdlib only), recovers every MAC input from the raw line bytes and never
re-serializes parsed JSON. The server never imports or calls it, and it is not an MCP tool.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, NoReturn

EXIT_CLEAN = 0
EXIT_TAMPER = 1
EXIT_USAGE = 2

KEY_ENV = "UNIFI_AUDIT_CHAIN_KEY"
SUBKEY_CONTEXT = b"unifi-fabric/audit-chain/v1"
DOMAIN = b"unifi-fabric-audit-chain\x00v1\x00"
ZERO_MAC = "0" * 64
CHAIN_FIELDS = ("chain", "seq", "prev", "mac")
CHAIN_START = "audit.chain_start"
SEAL = "audit.seal"
RECOVERED = "audit.recovered"
POLICY_EVENTS = ("policy.startup", "policy.refusal")
#: Largest key file read (bytes); a keyring is a few lines.
KEY_FILE_MAX = 65536

#: Tamper evidence: each makes the exit status 1.
FINDINGS = (
    "BAD_MAC",
    "SEQ_GAP",
    "PREV_MISMATCH",
    "DUP_SEQ",
    "UNCHAINED_LINE",
    "MISSING_SEAL",
    "ORPHAN_SEAL",
    "MALFORMED_LINE",
    "UNKNOWN_KID",
    "CHAIN_PREFIX_MISSING",
    "ANCHOR_MISSING",
    "ANCHOR_MISMATCH",
)
#: Reported, exit status unchanged.
WARNINGS = (
    "UNLINKED_CHAIN_START",
    "UNSEALED_POLICY_RECOVERED",
    "MALFORMED_LINE_RECOVERED",
    "TRUNCATED_TAIL",
    "CHAIN_PREFIX_MISSING_ALLOWED",
)

_KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HINT = re.compile(rb'"chain":"([0-9a-f]{32})"')
_ANCHOR = re.compile(r"([0-9a-f]{32}):(0|[1-9][0-9]{0,18}):([0-9a-f]{64})")


class UsageError(Exception):
    """A usage or key problem (exit 2). The message never holds a key, path or digest."""


# ----------------------------------------------------------------------------- keys
def _decode_key(text: str) -> bytes | None:
    if _KEY_RE.fullmatch(text) is None:
        return None
    try:
        raw = base64.b64decode(text + "=", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        return None
    return raw


def subkey_of(key: bytes) -> bytes:
    return hmac.digest(key, SUBKEY_CONTEXT, "sha256")


def kid_of(subkey: bytes) -> str:
    return hmac.digest(subkey, b"kid", "sha256").hex()[:8]


def read_key_file(path: str) -> list[bytes]:
    """The keys of one key file. Refused (``UsageError``) unless it is a regular file,
    not reached through a symlink, owned by the invoking user, with no group or other
    permission bits. Errors give the line number only."""
    refused = (
        "key file refused: it must be a regular file (not a symlink) owned by you "
        "with no group or other permission bits (0600 or 0400)"
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise UsageError(f"{refused} (it could not be opened)") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UsageError(refused)
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise UsageError(refused)
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise UsageError(refused)
        data = os.read(fd, KEY_FILE_MAX + 1)
    except OSError:
        raise UsageError(f"{refused} (it could not be read)") from None
    finally:
        os.close(fd)
    if len(data) > KEY_FILE_MAX:
        raise UsageError("key file is too large to be a keyring")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise UsageError("key file is not ASCII text") from None
    keys: list[bytes] = []
    for number, line in enumerate(text.splitlines(), start=1):
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        key = _decode_key(item)
        if key is None:
            raise UsageError(
                f"key file line {number}: not canonical unpadded base64url for 32 bytes"
            )
        keys.append(key)
    if not keys:
        raise UsageError("key file holds no key")
    return keys


def load_keys(key_files: Sequence[str], environ: dict[str, str] | None = None) -> dict[str, bytes]:
    """``kid -> subkey`` from the environment and the key files."""
    env = os.environ if environ is None else environ
    keys: list[bytes] = []
    value = env.get(KEY_ENV, "")
    if value.strip():
        key = _decode_key(value)
        if key is None:
            raise UsageError(f"{KEY_ENV} is not canonical unpadded base64url for 32 bytes")
        keys.append(key)
    for path in key_files:
        keys.extend(read_key_file(path))
    if not keys:
        raise UsageError(f"no key: set {KEY_ENV} or pass --key-file")
    ring: dict[str, bytes] = {}
    for key in keys:
        sub = subkey_of(key)
        ring[kid_of(sub)] = sub
    return ring


# ---------------------------------------------------------------------- raw line bytes
def top_level_members(data: bytes) -> list[tuple[bytes, int, int]] | None:
    """``(raw_key, start, end)`` of each top-level member of a one-line JSON object:
    ``data[start:end]`` is the member (``"key":value``) without its delimiters. ``None``
    when the bytes are not shaped like one object. Works on the raw bytes only (the
    caller has already checked the line parses as JSON)."""
    if len(data) < 2 or data[0] != 0x7B or data[-1] != 0x7D:
        return None
    members: list[tuple[bytes, int, int]] = []
    depth = 0
    in_str = esc = expect_key = False
    key_open = start = -1
    key: bytes | None = None
    last = len(data) - 1
    for i, b in enumerate(data):
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
                if key_open >= 0:
                    key, key_open = data[key_open + 1 : i], -1
            continue
        if b == 0x22:
            in_str = True
            if depth == 1 and expect_key:
                key_open = start = i
                expect_key = False
        elif b in (0x7B, 0x5B):
            depth += 1
            if i == 0:
                expect_key = True
        elif b in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                return None
            if depth == 0:
                if i != last:
                    return None
                if key is not None:
                    members.append((key, start, i))
                elif members:  # a trailing comma
                    return None
        elif b == 0x2C and depth == 1:
            if key is None:
                return None
            members.append((key, start, i))
            key, start, expect_key = None, -1, True
    if depth != 0 or in_str:
        return None
    return members


def mac_input(data: bytes) -> tuple[bytes, str] | None:
    """``(line bytes without the mac member, mac)`` recovered from the raw line bytes,
    or ``None`` when the line has no single well-formed top-level ``mac`` member."""
    members = top_level_members(data)
    if not members:
        return None
    found = [(i, m) for i, m in enumerate(members) if m[0] == b"mac"]
    if len(found) != 1:
        return None
    index, (_key, start, end) = found[0]
    if data[start : start + 6] != b'"mac":':
        return None
    value = data[start + 6 : end]
    if len(value) != 66 or value[:1] != b'"' or value[-1:] != b'"':
        return None
    mac = value[1:-1].decode("ascii", errors="replace")
    if _HEX64.fullmatch(mac) is None:
        return None
    if index > 0:
        cut = data[: start - 1] + data[end:]  # drop ',"mac":"..."'
    else:
        cut = data[:start] + data[end + 1 :] if len(members) > 1 else data[:start] + data[end:]
    return cut, mac


def _keys_unique(data: bytes) -> bool:
    members = top_level_members(data) or []
    seen: set[str] = set()
    for raw, _s, _e in members:
        try:
            name = json.loads(b'"' + raw + b'"')
        except ValueError:
            return False
        if name in seen:
            return False
        seen.add(name)
    return True


def record_mac(subkey: bytes, data: bytes) -> str:
    return hmac.digest(subkey, DOMAIN + data, "sha256").hex()


# ---------------------------------------------------------------------------- report
@dataclass
class Item:
    code: str
    where: str
    detail: str = ""
    chain: str | None = None
    seq: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "where": self.where,
            "chain": self.chain,
            "seq": self.seq,
            "detail": self.detail,
        }


@dataclass
class ChainInfo:
    kid: str | None = None
    subkey: bytes | None = field(default=None, repr=False)
    last_seq: int = -1
    last_mac: str = ""
    records: int = 0
    kid_reported: bool = False


@dataclass
class Report:
    findings: list[Item] = field(default_factory=list)
    warnings: list[Item] = field(default_factory=list)
    legacy_lines: int = 0
    chained_records: int = 0
    chains: dict[str, ChainInfo] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return EXIT_TAMPER if self.findings else EXIT_CLEAN

    def heads(self) -> list[str]:
        return [
            f"{cid}:{info.last_seq}:{info.last_mac}"
            for cid, info in self.chains.items()
            if info.last_seq >= 0
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": "tamper_evidence" if self.findings else "no_tamper_evidence",
            "exit": self.exit_code,
            "findings": [i.as_dict() for i in self.findings],
            "warnings": [i.as_dict() for i in self.warnings],
            "legacy_lines": self.legacy_lines,
            "chained_records": self.chained_records,
            "chains": [
                {"chain": cid, "kid": info.kid, "records": info.records, "head_seq": info.last_seq}
                for cid, info in self.chains.items()
            ],
            "heads": self.heads(),
        }


@dataclass
class _Pending:
    """A malformed line or an unsealed policy line, excused only when the first record
    (after any ``audit.chain_start``) of a candidate chain that follows it is
    ``audit.recovered`` (the fail-open rule)."""

    code: str
    where: str
    candidates: set[str] | None  # None: any chain
    decided: set[str] = field(default_factory=set)
    excused: bool = False
    sha: str = ""


Line = tuple[str, int, bytes, bool]  # (file, line number, bytes, has newline)


def _lines(paths: Sequence[str]) -> Iterator[Line]:
    for path in paths:
        with open(path, "rb") as fh:
            for number, raw in enumerate(fh, start=1):
                newline = raw.endswith(b"\n")
                yield path, number, raw[:-1] if newline else raw, newline


def _parse(data: bytes) -> dict[str, Any] | None:
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def _link_targets(lines: Iterable[Line]) -> set[tuple[str, int]]:
    """Pass 1: the ``(chain, seq)`` every ``audit.chain_start`` links to."""
    targets: set[tuple[str, int]] = set()
    for _p, _n, data, _nl in lines:
        if b'"audit.chain_start"' not in data:
            continue
        obj = _parse(data)
        if obj and obj.get("event") == CHAIN_START:
            chain, seq = obj.get("prev_chain"), obj.get("prev_seq")
            if isinstance(chain, str) and isinstance(seq, int) and not isinstance(seq, bool):
                targets.add((chain, seq))
    return targets


def _chain_fields_ok(obj: dict[str, Any]) -> bool:
    seq = obj.get("seq")
    return (
        isinstance(obj.get("chain"), str)
        and _HEX32.fullmatch(obj["chain"]) is not None
        and isinstance(seq, int)
        and not isinstance(seq, bool)
        and seq >= 0
        and isinstance(obj.get("prev"), str)
        and _HEX64.fullmatch(obj["prev"]) is not None
        and isinstance(obj.get("mac"), str)
        and _HEX64.fullmatch(obj["mac"]) is not None
    )


def verify(
    paths: Sequence[str],
    ring: dict[str, bytes],
    *,
    expect_heads: Sequence[tuple[str, int, str]] = (),
    allow_rotated_prefix: bool = False,
) -> Report:
    """Check the files (oldest first) in one linear pass after a link-target pre-pass.
    Memory is bounded by the number of chains, links, anchors and pending items."""
    report = Report()
    targets = _link_targets(_lines(paths)) | {(c, s) for c, s, _m in expect_heads}
    found: dict[tuple[str, int], str] = {}
    pending: list[_Pending] = []
    policy_waiting: dict[str, list[_Pending]] = {}
    seen_chained = False

    def finding(
        code: str, where: str, detail: str = "", chain: str | None = None, seq: int | None = None
    ) -> None:
        report.findings.append(Item(code, where, detail, chain, seq))

    def warning(
        code: str, where: str, detail: str = "", chain: str | None = None, seq: int | None = None
    ) -> None:
        report.warnings.append(Item(code, where, detail, chain, seq))

    for (path, number, data, newline), last in _last_flags(_lines(paths)):
        where = f"{path}:{number}"
        if not data:
            continue
        obj = _parse(data)
        if obj is None:
            if last and not newline:
                warning("TRUNCATED_TAIL", where, "the final line is cut (a cut tail)")
                continue
            hint = _HINT.search(data[:200])
            pending.append(
                _Pending("MALFORMED_LINE", where, {hint.group(1).decode()} if hint else None)
            )
            continue
        if not any(k in obj for k in CHAIN_FIELDS):
            event = obj.get("event")
            if not seen_chained:
                report.legacy_lines += 1
            elif event in POLICY_EVENTS:
                item = _Pending("MISSING_SEAL", where, None, sha=hashlib.sha256(data).hexdigest())
                pending.append(item)
                policy_waiting.setdefault(item.sha, []).append(item)
            else:
                finding("UNCHAINED_LINE", where, "a line without chain fields after chaining began")
            continue
        if not _chain_fields_ok(obj) or not _keys_unique(data):
            finding("BAD_MAC", where, "invalid or duplicated chain fields")
            seen_chained = True
            continue
        split = mac_input(data)
        cid, seq, prev, mac = obj["chain"], obj["seq"], obj["prev"], obj["mac"]
        event = obj.get("event")
        seen_chained = True
        report.chained_records += 1
        info = report.chains.get(cid)
        new_chain = info is None
        if info is None:
            info = report.chains[cid] = ChainInfo()
            if event == CHAIN_START:
                kid = obj.get("kid")
                info.kid = kid if isinstance(kid, str) else None
                info.subkey = ring.get(info.kid or "")
                if info.subkey is None:
                    info.kid_reported = True
                    finding("UNKNOWN_KID", where, "no key with this kid was given", cid, seq)
            else:
                code = (
                    "CHAIN_PREFIX_MISSING_ALLOWED"
                    if allow_rotated_prefix
                    else ("CHAIN_PREFIX_MISSING")
                )
                (warning if allow_rotated_prefix else finding)(
                    code,
                    where,
                    "the chain's first record here is not audit.chain_start "
                    "and no earlier file was given",
                    cid,
                    seq,
                )
        info.records += 1
        # MAC over the raw line bytes, mac member removed.
        mac_ok = False
        if split is not None and split[1] == mac:
            if info.subkey is not None:
                mac_ok = hmac.compare_digest(record_mac(info.subkey, split[0]), mac)
            elif not info.kid_reported:
                for kid, sub in ring.items():
                    if hmac.compare_digest(record_mac(sub, split[0]), mac):
                        info.kid, info.subkey, mac_ok = kid, sub, True
                        break
        if not mac_ok and not (info.kid_reported and info.subkey is None):
            finding("BAD_MAC", where, "the MAC does not match the line", cid, seq)
        # Position in the chain.
        advance = True
        if new_chain:
            if event == CHAIN_START:
                if seq != 0:
                    finding("SEQ_GAP", where, "audit.chain_start is not seq 0", cid, seq)
                if prev != ZERO_MAC:
                    finding("PREV_MISMATCH", where, "audit.chain_start prev is not zero", cid, seq)
        elif seq <= info.last_seq:
            finding("DUP_SEQ", where, f"seq {seq} after seq {info.last_seq}", cid, seq)
            advance = False
        elif seq > info.last_seq + 1:
            missing = seq - info.last_seq - 1
            finding("SEQ_GAP", where, f"{missing} record(s) missing before it", cid, seq)
        elif not hmac.compare_digest(prev, info.last_mac):
            finding("PREV_MISMATCH", where, "prev is not the previous record's mac", cid, seq)
        if advance:
            info.last_seq, info.last_mac = seq, mac
        if (cid, seq) in targets and (cid, seq) not in found:
            found[(cid, seq)] = mac
        # Links between chains.
        if event == CHAIN_START and new_chain:
            pc, ps, pm = obj.get("prev_chain"), obj.get("prev_seq"), obj.get("prev_mac")
            if pc is None and ps is None and pm is None:
                if len(report.chains) > 1:
                    warning("UNLINKED_CHAIN_START", where, "no link to an earlier chain", cid, seq)
            elif isinstance(pc, str) and isinstance(ps, int) and (pc, ps) in found:
                if not (isinstance(pm, str) and hmac.compare_digest(found[(pc, ps)], pm)):
                    finding("PREV_MISMATCH", where, "the linked record's mac differs", cid, seq)
            else:
                (warning if allow_rotated_prefix else finding)(
                    "CHAIN_PREFIX_MISSING_ALLOWED"
                    if allow_rotated_prefix
                    else "CHAIN_PREFIX_MISSING",
                    where,
                    "the record this chain links to is not in the files given",
                    cid,
                    seq,
                )
        # Seals: one seal consumes one earlier policy line with the same digest.
        if event == SEAL:
            sha = obj.get("sealed_sha256")
            waiting = policy_waiting.get(sha) if isinstance(sha, str) else None
            if waiting:
                item = waiting.pop(0)
                pending.remove(item)
            else:
                finding("ORPHAN_SEAL", where, "no earlier unsealed policy line matches", cid, seq)
        # Fail-open excuses: the first record of a chain after a pending item. A recovered
        # record excuses at most as many items as the records it says were lost (its MACed
        # lost_records, one per cut or unsealed line a fault leaves); any line beyond that
        # count is not a fault's doing and stays a finding.
        if event != CHAIN_START:
            lost = obj.get("lost_records")
            budget = lost if isinstance(lost, int) and not isinstance(lost, bool) else 0
            for item in pending:
                if item.excused or cid in item.decided:
                    continue
                if item.candidates is not None and cid not in item.candidates:
                    continue
                item.decided.add(cid)
                if event == RECOVERED and budget > 0:
                    item.excused = True
                    budget -= 1
    for item in pending:
        if item.code == "MISSING_SEAL":
            if item.excused:
                warning("UNSEALED_POLICY_RECOVERED", item.where, "followed by audit.recovered")
            else:
                finding("MISSING_SEAL", item.where, "a policy line with no audit.seal")
        elif item.excused:
            warning("MALFORMED_LINE_RECOVERED", item.where, "a cut record (fail-open)")
        else:
            finding("MALFORMED_LINE", item.where, "not one JSON object")
    for cid, seq, mac in expect_heads:
        where = f"anchor {cid}:{seq}"
        if (cid, seq) not in found:
            finding("ANCHOR_MISSING", where, "the anchored record is not in the files", cid, seq)
        elif not hmac.compare_digest(found[(cid, seq)], mac):
            finding("ANCHOR_MISMATCH", where, "the anchored record's mac differs", cid, seq)
    return report


def _last_flags(lines: Iterable[Line]) -> Iterator[tuple[Line, bool]]:
    """Each line with a flag: True for the last line of its file."""
    prev: Line | None = None
    for line in lines:
        if prev is not None:
            yield prev, prev[0] != line[0] or prev[1] + 1 != line[1]
        prev = line
    if prev is not None:
        yield prev, True


# ------------------------------------------------------------------------------- CLI
class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # noqa: ARG002 - arguments are never echoed
        self.print_usage(sys.stderr)
        sys.stderr.write(
            f"{self.prog}: usage error (arguments are not echoed; a key is never an "
            "argument: use UNIFI_AUDIT_CHAIN_KEY or --key-file)\n"
        )
        raise SystemExit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="unifi-fabric-audit-verify",
        description="Verify the tamper-evident audit hash chain (UNIFI_AUDIT_CHAIN). "
        "Exit 0: no tamper evidence; 1: tamper evidence; 2: usage or key error.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--key-file",
        action="append",
        default=[],
        metavar="PATH",
        help="keyring file: one key per line, mode 0600 or 0400, owned by you, "
        "not a symlink (repeatable); UNIFI_AUDIT_CHAIN_KEY is read too",
    )
    parser.add_argument(
        "--expect-head",
        action="append",
        default=[],
        metavar="CHAIN:SEQ:MAC",
        help="an anchored head that must be present unchanged (repeatable)",
    )
    parser.add_argument(
        "--allow-rotated-prefix",
        action="store_true",
        help="report a chain whose start is not in the files as a warning (still counted)",
    )
    parser.add_argument("--print-head", action="store_true", help="print each chain's head")
    parser.add_argument("--json", action="store_true", help="one JSON report on stdout")
    parser.add_argument("files", nargs="+", metavar="FILE", help="audit files, oldest first")
    return parser


def _anchor(text: str) -> tuple[str, int, str]:
    match = _ANCHOR.fullmatch(text)
    if match is None:
        raise UsageError("--expect-head must be CHAIN:SEQ:MAC (32 hex, a number, 64 hex)")
    return match.group(1), int(match.group(2)), match.group(3)


def _print_text(report: Report, print_head: bool, allowed: bool) -> None:
    out = sys.stdout
    for item in report.findings:
        out.write(f"FINDING {item.code} {item.where} {item.detail}\n")
    for item in report.warnings:
        out.write(f"WARNING {item.code} {item.where} {item.detail}\n")
    if report.legacy_lines:
        out.write(
            f"INFO LEGACY_LINES {report.legacy_lines} unverified line(s) before the first "
            "chained record\n"
        )
    allowed_count = sum(1 for w in report.warnings if w.code == "CHAIN_PREFIX_MISSING_ALLOWED")
    if allowed:
        out.write(f"INFO CHAIN_PREFIX_MISSING allowed by --allow-rotated-prefix: {allowed_count}\n")
    for cid, info in report.chains.items():
        out.write(f"CHAIN {cid} kid={info.kid or '-'} records={info.records}\n")
    if print_head:
        for head in report.heads():
            out.write(f"HEAD {head}\n")
    verdict = "TAMPER EVIDENCE" if report.findings else "NO TAMPER EVIDENCE"
    out.write(
        f"RESULT {verdict}: {len(report.findings)} finding(s), {len(report.warnings)} "
        f"warning(s), {report.chained_records} chained record(s)\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        anchors = [_anchor(a) for a in args.expect_head]
        ring = load_keys(args.key_file)
        for path in args.files:
            try:
                st = os.stat(path)
            except OSError:
                raise UsageError("an audit file could not be read") from None
            if not stat.S_ISREG(st.st_mode):
                raise UsageError("an audit file is not a regular file")
        report = verify(
            args.files,
            ring,
            expect_heads=anchors,
            allow_rotated_prefix=args.allow_rotated_prefix,
        )
    except UsageError as exc:
        sys.stderr.write(f"unifi-fabric-audit-verify: {exc}\n")
        return EXIT_USAGE
    except OSError:
        sys.stderr.write("unifi-fabric-audit-verify: an audit file could not be read\n")
        return EXIT_USAGE
    if args.json:
        doc = report.as_dict()
        doc["allowed_rotated_prefix"] = sum(
            1 for w in report.warnings if w.code == "CHAIN_PREFIX_MISSING_ALLOWED"
        )
        sys.stdout.write(json.dumps(doc, sort_keys=True) + "\n")
    else:
        _print_text(report, args.print_head, args.allow_rotated_prefix)
    return report.exit_code


def cli() -> NoReturn:
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover - ``python -m unifi_fabric.audit_verify``
    cli()
