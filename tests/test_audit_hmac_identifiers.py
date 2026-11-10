"""UNIFI_AUDIT_HMAC_IDENTIFIERS: a planted client MAC or user id never reaches an audit
record in clear when the flag is on (every field position, both formats, every sink).

Planted values and the key are generated at run time; no identifier or key literal is
stored in this file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from unifi_fabric.audit import (
    AuditStream,
    FileSink,
    StderrSink,
    audit_call,
    close_audit_stream,
    configure_audit_stream,
)
from unifi_fabric.audit_identifiers import DOMAIN, IdentifierHasher
from unifi_fabric.audit_remote import RemoteConfig, RemoteSink
from unifi_fabric.config import Settings
from unifi_fabric.macs import MAC_IN_TEXT_RE as MAC_RE

TOKEN = re.compile(r"hmac:[0-9a-f]{32}")


def _key_text() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def _key_bytes(text: str) -> bytes:
    return base64.b64decode(text + "=", altchars=b"-_")


class Planted:
    """One random client MAC in every written form, and one random user id."""

    def __init__(self) -> None:
        raw = os.urandom(6)
        octets = [f"{b:02x}" for b in raw]
        self.hex = "".join(octets)
        self.forms = {
            "colon": ":".join(octets),
            "colon_upper": ":".join(octets).upper(),
            "dash": "-".join(octets),
            "dot": ".".join(self.hex[i : i + 4] for i in range(0, 12, 4)),
            "url": "%3A".join(octets),
            "bare": self.hex,
        }
        self.user = "u" + os.urandom(5).hex() + "7"
        self.email = f"op{os.urandom(3).hex()}@example.test"

    def clear_hits(self, text: str) -> list[str]:
        """Every planted value found in ``text`` (any MAC form, any letter case)."""
        low = text.lower()
        hits = [name for name, form in self.forms.items() if form.lower() in low]
        hits += [v for v in (self.user, self.email) if v.lower() in low]
        return hits


def _write_everything(stream: AuditStream, p: Planted) -> None:
    body = {
        "mac": p.forms["bare"],
        "clientMac": p.forms["colon_upper"],
        "macs": [p.forms["dash"], p.forms["bare"]],
        "user_id": p.user,
        "email": p.email,
        "note": f"seen {p.forms['dot']} and {p.forms['colon']} today",
        p.forms["colon"]: {"nested": {"sta_mac": p.forms["bare"]}},
    }
    stream.startup("9.9.9")
    with audit_call("block_client"):
        for path in (
            f"/proxy/network/api/s/default/cmd/stamgr/{p.forms['colon']}",
            f"/v1/sites/x/clients/{p.forms['bare']}/block",
            f"/v1/sites/x/clients/{p.forms['url']}?mac={p.forms['bare']}",
            f"/v1/users/{p.user}/roles",
            f"/v1/admins/{p.email}",
            f"/v1/sites/x/devices/{p.forms['dash'].upper()}",
        ):
            stream.record(
                method="POST",
                path=path,
                outcome="error",
                status=400,
                reason=f"client {p.forms['colon']} ({p.forms['dash']}) refused",
                body=body,
            )
        stream.call("block_client", {"mac": p.forms["bare"], "user": p.user, "body": body})
        stream.error("block_client", ValueError(f"unknown client {p.forms['colon_upper']}"))


@pytest.fixture
def key_text() -> str:
    return _key_text()


def _stream(sink: Any, fmt: str, key_text: str | None) -> AuditStream:
    return AuditStream(
        sink=sink,
        fmt=fmt,
        level="debug",
        calls=True,
        identifiers=IdentifierHasher(_key_bytes(key_text)) if key_text else None,
    )


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_planted_mac_and_user_never_in_clear_in_the_file(
    tmp_path: Path, fmt: str, key_text: str
) -> None:
    p = Planted()
    path = tmp_path / "audit.log"
    _write_everything(_stream(FileSink(path=str(path)), fmt, key_text), p)
    text = path.read_text(encoding="utf-8")
    assert text.count("\n") == 9
    assert p.clear_hits(text) == []
    assert key_text not in text
    assert len(set(TOKEN.findall(text))) >= 3  # MAC, user id, email tokens


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_flag_off_keeps_identifiers_verbatim(tmp_path: Path, fmt: str) -> None:
    """Control: the same records without the flag carry every planted value."""
    p = Planted()
    path = tmp_path / "audit.log"
    _write_everything(_stream(FileSink(path=str(path)), fmt, None), p)
    text = path.read_text(encoding="utf-8")
    assert {"colon", "bare", "dash", "dot"} <= set(p.clear_hits(text))
    assert p.user in text and p.email in text
    assert "hmac:" not in text


def test_planted_mac_never_in_clear_on_stderr(key_text: str) -> None:
    p = Planted()
    out = io.StringIO()
    _write_everything(_stream(StderrSink(stream=lambda: out), "json", key_text), p)
    assert out.getvalue() and p.clear_hits(out.getvalue()) == []


def test_planted_mac_never_in_clear_on_the_remote_sink(key_text: str) -> None:
    p = Planted()
    sink = RemoteSink(RemoteConfig(url="http://127.0.0.1:9/a", plaintext=True), start=False)
    _write_everything(_stream(sink, "json", key_text), p)
    lines = b"\n".join(line for _, line in sink.sender._buf).decode("utf-8")
    assert sink.sender.buffered() == 9
    assert p.clear_hits(lines) == []


def test_every_form_of_one_mac_gives_one_token(key_text: str) -> None:
    p = Planted()
    h = IdentifierHasher(_key_bytes(key_text))
    tokens = {h.text(form) for name, form in p.forms.items() if name != "bare"}
    tokens.add(h.path(p.forms["bare"]))
    assert len(tokens) == 1 and TOKEN.fullmatch(tokens.pop())


def test_tokens_are_stable_per_key_and_differ_across_installations() -> None:
    p = Planted()
    k1, k2 = _key_text(), _key_text()
    a = IdentifierHasher(_key_bytes(k1)).text(p.forms["colon"])
    assert a == IdentifierHasher(_key_bytes(k1)).text(p.forms["colon"])
    assert a != IdentifierHasher(_key_bytes(k2)).text(p.forms["colon"])


def test_token_is_domain_separated_from_a_plain_hmac(key_text: str) -> None:
    p = Planted()
    key = _key_bytes(key_text)
    token = IdentifierHasher(key).text(p.forms["colon"])
    plain = hmac.new(key, p.hex.encode(), hashlib.sha256).hexdigest()[:32]
    assert token != f"hmac:{plain}"
    expected = hmac.new(key, DOMAIN + b"mac\x00" + p.hex.encode(), hashlib.sha256).hexdigest()
    assert token == f"hmac:{expected[:32]}"


@pytest.mark.parametrize(
    "text",
    [
        "fe80::1:2:3:4:5:6",  # IPv6, not a MAC
        "2001:db8:aa:bb:cc:dd:ee:ff",
        "0123456789abcdef0123456789abcdef",  # longer hex id
        "0" * 20 + "abcd",  # 24-hex object id (synthetic, epoch-zero timestamp)
        "12:30:45",  # a time
    ],
)
def test_non_mac_shapes_are_left_alone(text: str, key_text: str) -> None:
    h = IdentifierHasher(_key_bytes(key_text))
    assert h.text(text) == text
    assert MAC_RE.search(text) is None


def test_route_vocabulary_is_kept(key_text: str) -> None:
    h = IdentifierHasher(_key_bytes(key_text))
    assert h.path("/v1/users/search") == "/v1/users/search"
    assert h.path("/proxy/network/api/s/default/rest/user") == (
        "/proxy/network/api/s/default/rest/user"
    )


def test_hasher_repr_hides_the_key(key_text: str) -> None:
    h = IdentifierHasher(_key_bytes(key_text))
    assert key_text not in repr(h) and "hidden" in repr(h)


# ------------------------------------------------------------------------ settings path
def test_flag_requires_the_installation_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UNIFI_AUDIT_HMAC_KEY", raising=False)
    with pytest.raises(ValueError, match="UNIFI_AUDIT_HMAC_IDENTIFIERS=true requires"):
        Settings(api_key="k-test", audit_hmac_identifiers="true")


def test_flag_wires_from_settings_and_marks_the_startup_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _key_text()
    monkeypatch.setenv("UNIFI_AUDIT_HMAC_KEY", key)
    path = tmp_path / "a.log"
    p = Planted()
    stream = configure_audit_stream(
        Settings(api_key="k-test", audit_log=str(path), audit_hmac_identifiers="1")
    )
    assert stream is not None and stream.identifiers is not None
    stream.startup("9.9.9")
    stream.record(method="POST", path=f"/clients/{p.forms['colon']}", outcome="success", status=200)
    close_audit_stream(stream)
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert lines[0]["identifiers"] == "hmac"
    assert TOKEN.search(lines[1]["path"]) and p.clear_hits(path.read_text()) == []
    assert key not in path.read_text()


def test_flag_off_by_default_leaves_startup_record_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    stream = configure_audit_stream(Settings(api_key="k-test", audit_log=str(path)))
    assert stream is not None and stream.identifiers is None
    stream.startup("9.9.9")
    record = json.loads(path.read_text())
    assert "identifiers" not in record and "remote_endpoint" not in record


def test_mac_text_pattern_is_linear_on_adversarial_input():
    """The in-text MAC pattern has only fixed bounded repeats, so near-miss runs of any
    length stay linear: a hundred thousand almost-MACs finish well inside the bound."""
    import time

    for unit in ("aa:bb:cc:dd:ee:f", "aa-bb-cc-dd-ee-", "aabb.ccdd.eef", "aa:bb:cc:dd:ee:ff:"):
        subject = (unit * 8_000) + "!"
        started = time.perf_counter()
        MAC_RE.sub("x", subject)
        assert time.perf_counter() - started < 2.0, unit
