"""The ``remote`` audit sink: settings, wiring, TLS fail-closed delivery and no leaks.

Real sockets on the loopback interface; certificates are generated at run time (no key
material is stored in the repository).
"""

from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import json
import logging
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from unifi_fabric import audit_remote, switches
from unifi_fabric.audit import (
    AUDIT_UNAVAILABLE,
    SINKS,
    AuditStream,
    FileSink,
    build_audit_stream,
    close_audit_stream,
    configure_audit_stream,
)
from unifi_fabric.audit_remote import RemoteConfig, RemoteSender, RemoteSink
from unifi_fabric.config import AUDIT_SINKS, Settings

# A path segment that must never reach any output (it stands in for a collector token).
PATH_MARK = "collector-path-" + "q7v"


def _settings(**kw: Any) -> Settings:
    return Settings(api_key="k-test", **kw)


def _wait(cond: Callable[[], bool], polls: int = 1500) -> bool:
    """Poll ``cond`` a fixed number of times (20 ms apart), then fail the test instead of
    hanging.

    No pytest timeout plugin or job limit is configured, so an unbounded poll would hold a
    shard until the runner's own limit; a poll count bounds it without a clock.
    """
    for _ in range(polls):
        if cond():
            return True
        time.sleep(0.02)
    if cond():
        return True
    raise AssertionError(f"condition not met after {polls} polls")


def test_wait_fails_instead_of_hanging():
    with pytest.raises(AssertionError, match="not met after"):
        _wait(lambda: False, polls=5)
    assert _wait(lambda: True)


# ------------------------------------------------------------------------- collector
class _Collector:
    """A minimal NDJSON collector (HTTP or HTTPS, optional client-certificate check)."""

    def __init__(self, ctx: ssl.SSLContext | None = None, status: int = 200) -> None:
        self.requests: list[dict[str, Any]] = []
        self.status = status
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a: Any) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                owner.requests.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                        "peer_cert": (
                            self.connection.getpeercert()
                            if isinstance(self.connection, ssl.SSLSocket)
                            else None
                        ),
                    }
                )
                self.send_response(owner.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self) -> tuple[socket.socket, Any]:
                sock, addr = self.socket.accept()
                if ctx is not None:
                    sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
                return sock, addr

            def handle_error(self, *_a: Any) -> None:
                return

        self._server = Server(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Collector:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for r in self.requests for line in r["body"].decode().splitlines()]


# ------------------------------------------------------------------------- certificates
@dataclass(frozen=True)
class _Certs:
    ca: Path
    other_ca: Path
    server_cert: Path
    server_key: Path
    wrong_cert: Path
    wrong_key: Path
    client_cert: Path
    client_key: Path


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> _Certs:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    directory = tmp_path_factory.mktemp("audit-remote-sink-certs")
    now = dt.datetime.now(dt.UTC)

    def name(cn: str) -> Any:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def build(subject: str, issuer_key: Any, issuer: Any, key: Any, *, ca: bool) -> Any:
        b = (
            x509.CertificateBuilder()
            .subject_name(name(subject))
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
        )
        return b

    def ca_pair(cn: str) -> tuple[Any, Any]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            build(cn, key, name(cn), key, ca=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256())
        )
        return key, cert

    def leaf(ca_key: Any, ca_cert: Any, cn: str, usage: Any, sans: list[Any]) -> tuple[Any, Any]:
        key = ec.generate_private_key(ec.SECP256R1())
        b = (
            build(cn, ca_key, ca_cert.subject, key, ca=False)
            .add_extension(x509.ExtendedKeyUsage([usage]), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
            )
        )
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName(sans), False)
        return key, b.sign(ca_key, hashes.SHA256())

    def write(path: Path, cert: Any = None, key: Any = None) -> Path:
        if cert is not None:
            path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        else:
            path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            path.chmod(0o600)
        return path

    ca_key, ca_cert = ca_pair("sink-test-ca")
    _, other_cert = ca_pair("sink-other-ca")
    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    s_key, s_cert = leaf(ca_key, ca_cert, "collector", ExtendedKeyUsageOID.SERVER_AUTH, sans)
    w_key, w_cert = leaf(
        ca_key, ca_cert, "wrong", ExtendedKeyUsageOID.SERVER_AUTH, [x509.DNSName("other.test")]
    )
    c_key, c_cert = leaf(ca_key, ca_cert, "audit-client", ExtendedKeyUsageOID.CLIENT_AUTH, [])
    return _Certs(
        ca=write(directory / "ca.pem", ca_cert),
        other_ca=write(directory / "other-ca.pem", other_cert),
        server_cert=write(directory / "server.pem", s_cert),
        server_key=write(directory / "server.key", key=s_key),
        wrong_cert=write(directory / "wrong.pem", w_cert),
        wrong_key=write(directory / "wrong.key", key=w_key),
        client_cert=write(directory / "client.pem", c_cert),
        client_key=write(directory / "client.key", key=c_key),
    )


def _server_ctx(certs: _Certs, *, wrong_name: bool = False, mtls: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if wrong_name:
        ctx.load_cert_chain(str(certs.wrong_cert), str(certs.wrong_key))
    else:
        ctx.load_cert_chain(str(certs.server_cert), str(certs.server_key))
    if mtls:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(str(certs.ca))
    return ctx


def _record(event: str = "call", **extra: Any) -> dict[str, Any]:
    return {"schema_version": "1", "timestamp_utc": "2026-01-01T00:00:00+00:00", "event": event}


def _sender(cfg: RemoteConfig, attempts: list[dict[str, Any]]) -> RemoteSender:
    return RemoteSender(cfg, sleep=lambda _s: None, on_attempt=attempts.append)


@pytest.fixture
def tracked_streams() -> Iterator[list[AuditStream]]:
    streams: list[AuditStream] = []
    yield streams
    for stream in streams:
        close_audit_stream(stream)


# ============================================================================ settings
def test_remote_is_an_accepted_sink_value() -> None:
    assert "remote" in SINKS and "remote" in AUDIT_SINKS
    settings = _settings(audit_sink="remote", audit_remote_url="https://collector.test/a")
    assert settings.audit_sink == "remote"


def test_remote_sink_requires_a_url() -> None:
    with pytest.raises(ValueError, match="UNIFI_AUDIT_REMOTE_URL is required"):
        _settings(audit_sink="remote")


def test_remote_sink_requires_json_format() -> None:
    with pytest.raises(ValueError, match="requires UNIFI_AUDIT_LOG_FORMAT=json"):
        _settings(
            audit_sink="remote",
            audit_remote_url="https://collector.test/a",
            audit_log_format="text",
        )


def test_remote_sink_with_an_audit_file_path_is_the_normal_configuration(
    tmp_path: Path,
) -> None:
    settings = _settings(
        audit_sink="remote",
        audit_remote_url="https://collector.test/a",
        audit_log=str(tmp_path / "a.log"),
    )
    assert settings.audit_sink == "remote" and settings.audit_log.endswith("a.log")


@pytest.mark.parametrize("sink", ["none", "stderr"])
def test_a_sink_that_ignores_the_audit_file_path_is_still_refused(
    sink: str, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match=f"UNIFI_AUDIT_SINK={sink} conflicts with UNIFI_AUDIT_LOG"):
        _settings(audit_sink=sink, audit_log=str(tmp_path / "a.log"))


def test_a_remote_setting_without_the_remote_sink_is_refused() -> None:
    with pytest.raises(ValueError, match="UNIFI_AUDIT_REMOTE_URL is set but UNIFI_AUDIT_SINK"):
        _settings(audit_remote_url="https://collector.test/a")
    # The default value written out explicitly is not "set".
    _settings(audit_remote_plaintext="false")


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"audit_remote_url": f"http://collector.test/{PATH_MARK}"}, "PLAINTEXT=true"),
        ({"audit_remote_url": f"https://u:{PATH_MARK}@collector.test/a"}, "credentials"),
        ({"audit_remote_url": f"https://collector.test/a?k={PATH_MARK}"}, "query string"),
        ({"audit_remote_url": f"https://collector.test/a#{PATH_MARK}"}, "fragment"),
        ({"audit_remote_url": f"ftp://collector.test/{PATH_MARK}"}, "http(s)"),
        ({"audit_remote_url": f"https://collector.test:{PATH_MARK}/a"}, "port"),
        (
            {
                "audit_remote_url": f"https://collector.test/{PATH_MARK}",
                "audit_remote_plaintext": "true",
            },
            "requires an http://",
        ),
        (
            {
                "audit_remote_url": f"http://collector.test/{PATH_MARK}",
                "audit_remote_plaintext": "true",
                "audit_remote_ca_file": f"/etc/{PATH_MARK}.pem",
            },
            "must be unset",
        ),
        (
            {
                "audit_remote_url": "https://collector.test/a",
                "audit_remote_cert_file": f"/etc/{PATH_MARK}.pem",
            },
            "together",
        ),
        (
            {
                "audit_remote_url": "https://collector.test/a",
                "audit_remote_batch_max_bytes": "1023",
            },
            "at least 1024",
        ),
        (
            {"audit_remote_url": "https://collector.test/a", "audit_remote_max_attempts": "0"},
            "UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS",
        ),
    ],
)
def test_remote_configuration_errors_name_the_setting_never_the_value(
    kw: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=re.escape(message)) as err:
        _settings(audit_sink="remote", **kw)
    assert PATH_MARK not in str(err.value)


@pytest.mark.parametrize(
    "field", ["audit_remote_retry_backoff_seconds", "audit_remote_flush_interval_seconds"]
)
@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "abc", "1e999", "١"])
def test_remote_durations_must_be_finite_positive_numbers(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=f"UNIFI_{field.upper()} must be a number") as err:
        _settings(
            audit_sink="remote", audit_remote_url="https://collector.test/a", **{field: value}
        )
    assert "the value is not shown here" in str(err.value)


def test_remote_durations_accept_fractions() -> None:
    s = _settings(
        audit_sink="remote",
        audit_remote_url="https://collector.test/a",
        audit_remote_flush_interval_seconds="0.25",
        audit_remote_retry_backoff_seconds="2",
    )
    assert (s.audit_remote_flush_interval_seconds, s.audit_remote_retry_backoff_seconds) == (
        0.25,
        2.0,
    )


@pytest.mark.parametrize("field", ["audit_remote_plaintext", "audit_hmac_identifiers"])
@pytest.mark.parametrize(
    "spelling", [*switches.TRUE_VALUES, *switches.FALSE_VALUES, "TRUE", "  off\t"]
)
def test_new_audit_switches_use_the_shared_boolean_parser(
    monkeypatch: pytest.MonkeyPatch, field: str, spelling: str
) -> None:
    env = f"UNIFI_{field.upper()}"
    monkeypatch.setenv(env, spelling)
    expected = spelling.strip().lower() in switches.TRUE_VALUES
    if field == "audit_remote_plaintext":
        monkeypatch.setenv("UNIFI_AUDIT_SINK", "remote")
        monkeypatch.setenv(
            "UNIFI_AUDIT_REMOTE_URL", "http://c.test/a" if expected else "https://c.test/a"
        )
    elif expected:
        monkeypatch.setenv("UNIFI_AUDIT_HMAC_KEY", "A" * 42 + "A")
    assert getattr(Settings(api_key="k-test"), field) is expected
    assert switches.env_flag(env, not expected) is expected


@pytest.mark.parametrize("field", ["audit_remote_plaintext", "audit_hmac_identifiers"])
def test_new_audit_switches_refuse_a_malformed_value(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    env = f"UNIFI_{field.upper()}"
    monkeypatch.setenv(env, "maybe")
    with pytest.raises(ValueError, match=env):
        Settings(api_key="k-test")


def test_settings_repr_never_shows_remote_url_or_tls_paths() -> None:
    s = _settings(
        audit_sink="remote",
        audit_remote_url=f"https://collector.test/{PATH_MARK}",
        audit_remote_ca_file=f"/etc/{PATH_MARK}-ca.pem",
        audit_remote_cert_file=f"/etc/{PATH_MARK}-c.pem",
        audit_remote_key_file=f"/etc/{PATH_MARK}-k.pem",
    )
    assert PATH_MARK not in repr(s) and PATH_MARK not in str(s)


# ============================================================================ wiring
def test_build_audit_stream_selects_the_remote_sink(tracked_streams: list[AuditStream]) -> None:
    stream = build_audit_stream(
        _settings(audit_sink="remote", audit_remote_url=f"https://collector.test/{PATH_MARK}")
    )
    assert stream is not None
    tracked_streams.append(stream)
    assert isinstance(stream.sink, RemoteSink)
    assert stream.sink.endpoint == "https://collector.test:443"
    assert PATH_MARK not in repr(stream)


def test_plaintext_end_to_end_through_the_audit_stream(
    tracked_streams: list[AuditStream],
) -> None:
    with _Collector() as collector:
        stream = configure_audit_stream(
            _settings(
                audit_sink="remote",
                audit_calls=True,
                audit_remote_plaintext="true",
                audit_remote_url=f"http://127.0.0.1:{collector.port}/{PATH_MARK}/ingest",
                audit_remote_flush_interval_seconds="0.05",
            )
        )
        assert stream is not None
        tracked_streams.append(stream)
        stream.startup("9.9.9")
        stream.record(method="POST", path="/proxy/x?token=1", outcome="success", status=200)
        stream.call("list_sites", {"a": "café   line"})
        stream.policy_record(
            json.dumps(
                {"schema_version": "1", "timestamp_utc": "t", "event": "policy.startup", "x": 1},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        assert _wait(lambda: len(collector.records()) >= 4)
    records = collector.records()
    assert [r["event"] for r in records] == ["startup", "audit", "call", "policy.startup"]
    startup = records[0]
    assert startup["sink"] == "remote"
    assert startup["remote_endpoint"] == f"http://127.0.0.1:{collector.port}"
    assert collector.requests[0]["path"] == f"/{PATH_MARK}/ingest"
    for request in collector.requests:
        h = request["headers"]
        assert h["content-type"] == "application/x-ndjson"
        assert h["x-audit-schema-version"] == "1"
        body = request["body"].decode()
        assert body.endswith("\n")
        for line in body[:-1].split("\n"):
            obj = json.loads(line)
            assert line == json.dumps(
                obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            )
    assert not stream.unavailable


def test_tls_end_to_end_with_pinned_ca_and_client_certificate(
    certs: _Certs, tracked_streams: list[AuditStream]
) -> None:
    with _Collector(_server_ctx(certs, mtls=True)) as collector:
        stream = configure_audit_stream(
            _settings(
                audit_sink="remote",
                audit_remote_url=f"https://localhost:{collector.port}/ingest",
                audit_remote_ca_file=str(certs.ca),
                audit_remote_cert_file=str(certs.client_cert),
                audit_remote_key_file=str(certs.client_key),
                audit_remote_flush_interval_seconds="0.05",
            )
        )
        assert stream is not None
        tracked_streams.append(stream)
        stream.record(method="DELETE", path="/x", outcome="success", status=204)
        assert _wait(lambda: len(collector.records()) >= 1)
    assert collector.records()[0]["event"] == "audit"
    peer = collector.requests[0]["peer_cert"]
    assert peer and ((("commonName", "audit-client"),),) == peer["subject"]


@pytest.mark.parametrize(
    ("case", "ca", "wrong_name"),
    [("untrusted_ca", "other", False), ("hostname_mismatch", "valid", True)],
)
def test_tls_errors_fail_closed(
    certs: _Certs, case: str, ca: str, wrong_name: bool, caplog: pytest.LogCaptureFixture
) -> None:
    attempts: list[dict[str, Any]] = []
    with _Collector(_server_ctx(certs, wrong_name=wrong_name)) as collector:
        cfg = RemoteConfig(
            url=f"https://localhost:{collector.port}/{PATH_MARK}",
            ca_file=str(certs.ca if ca == "valid" else certs.other_ca),
            max_attempts=2,
        )
        sender = _sender(cfg, attempts)
        sender.emit(_record())
        with caplog.at_level(logging.DEBUG, logger="unifi_fabric.audit_remote"):
            assert sender.pump() is False
    assert collector.requests == []  # nothing was ever sent over the failed handshake
    assert [a["status"] for a in attempts] == [None, None]
    assert {a["error"] for a in attempts} == {"SSLCertVerificationError"}
    assert sender.notice == AUDIT_UNAVAILABLE
    assert PATH_MARK not in caplog.text and str(certs.ca) not in caplog.text
    assert f"https://localhost:{collector.port}" in caplog.text


def test_tls_never_falls_back_to_plaintext() -> None:
    attempts: list[dict[str, Any]] = []
    with _Collector() as collector:  # a plaintext HTTP server behind an https:// URL
        sender = _sender(
            RemoteConfig(url=f"https://127.0.0.1:{collector.port}/a", max_attempts=1), attempts
        )
        sender.emit(_record())
        sender.pump()
    assert collector.requests == []
    assert attempts[0]["status"] is None and sender.failing


def test_unreadable_tls_file_is_a_transport_error_of_the_attempt(tmp_path: Path) -> None:
    attempts: list[dict[str, Any]] = []
    missing = tmp_path / f"{PATH_MARK}.pem"
    sender = _sender(
        RemoteConfig(url="https://127.0.0.1:9/a", ca_file=str(missing), max_attempts=2), attempts
    )
    sender.emit(_record())
    assert sender.pump() is False
    assert [a["error"] for a in attempts] == ["FileNotFoundError", "FileNotFoundError"]


def test_verification_cannot_be_disabled() -> None:
    sender = RemoteSender(RemoteConfig(url="https://collector.test/a"))
    conn = sender._connection()
    ctx = conn._context  # type: ignore[attr-defined]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


# ============================================================================ notice
def test_stream_notice_follows_the_remote_sink_state() -> None:
    sink = RemoteSink(RemoteConfig(url="http://127.0.0.1:9/a", plaintext=True), start=False)
    stream = AuditStream(sink=sink)
    assert not stream.unavailable and stream.probe() is False
    sink.sender._failing = True
    assert stream.unavailable and stream.probe() is True


def test_buffer_overflow_is_drop_newest_and_never_blocks() -> None:
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)  # accepts, never answers: the one in-flight batch stalls
    port = blocker.getsockname()[1]
    sink = RemoteSink(
        RemoteConfig(
            url=f"http://127.0.0.1:{port}/a",
            plaintext=True,
            buffer_max_records=5,
            flush_interval=0.01,
        )
    )
    stream = AuditStream(sink=sink)
    try:
        for _ in range(500):  # returns although the collector never answers
            stream.record(method="POST", path="/x", outcome="success", status=200)
        assert stream.unavailable and stream.probe()
        events = sink.sender.buffered_events()
        assert len([e for e in events if not e.startswith("audit_remote_")]) <= 5
    finally:
        sink.close()
        blocker.close()


def test_close_stops_the_worker() -> None:
    sink = RemoteSink(RemoteConfig(url="http://127.0.0.1:9/a", plaintext=True, flush_interval=0.01))
    sink.close()
    assert sink._thread is not None
    sink._thread.join()
    assert not sink._thread.is_alive()


def test_contract_defaults_are_the_settings_defaults() -> None:
    fields = Settings.model_fields
    for env, default in audit_remote.DEFAULTS.items():
        value = fields[env.removeprefix("UNIFI_").lower()].default
        if default is None:
            assert value == ""
        elif default in {"true", "false"}:
            assert value is (default == "true")
        else:
            assert value == type(value)(default)


# ===================================================== S1: the local file is always first
def _file_and_remote(tmp_path: Path, url: str, **cfg: Any) -> tuple[AuditStream, Path, RemoteSink]:
    log = tmp_path / "audit.jsonl"
    remote = RemoteSink(
        RemoteConfig(url=url, plaintext=True, **cfg), start=False, sleep=lambda _s: None
    )
    stream = AuditStream(sink=FileSink(str(log)), remote_copy=remote, calls=True)
    return stream, log, remote


def _file_records(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_remote_with_audit_log_builds_the_file_sink_first_and_ships_after(
    tmp_path: Path, tracked_streams: list[AuditStream]
) -> None:
    stream = build_audit_stream(
        _settings(
            audit_sink="remote",
            audit_log=str(tmp_path / "a.log"),
            audit_remote_plaintext="true",
            audit_remote_url="http://127.0.0.1:9/a",
        )
    )
    assert stream is not None
    tracked_streams.append(stream)
    assert isinstance(stream.sink, FileSink) and isinstance(stream.remote_copy, RemoteSink)
    assert stream.path == str(tmp_path / "a.log")
    stream.startup("9.9.9")
    startup = _file_records(tmp_path / "a.log")[0]
    assert startup["sink"] == "remote" and startup["remote_endpoint"] == "http://127.0.0.1:9"
    assert "file_mode" in startup


def test_collector_outage_loses_no_local_record(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with _Collector() as down:
        port = down.port  # closed again on exit: connection refused
    stream, log, remote = _file_and_remote(tmp_path, f"http://127.0.0.1:{port}/a", max_attempts=2)
    for i in range(25):
        stream.call(f"tool_{i:02d}")
    assert remote.sender.pump() is False  # every attempt failed, the batch was dropped
    assert stream.unavailable  # the notice follows the remote failure
    assert [r["tool"] for r in _file_records(log)] == [f"tool_{i:02d}" for i in range(25)]
    assert PATH_MARK not in caplog.text


def test_local_file_order_matches_the_order_shipped(tmp_path: Path) -> None:
    with _Collector() as collector:
        stream, log, remote = _file_and_remote(
            tmp_path, f"http://127.0.0.1:{collector.port}/a", batch_max_records=7
        )
        for i in range(30):
            stream.call(f"tool_{i:02d}")
        assert remote.sender.pump() is True
    local = [r["tool"] for r in _file_records(log)]
    shipped = [r["tool"] for r in collector.records()]
    assert local == shipped == [f"tool_{i:02d}" for i in range(30)]
    # the collector copy is the same record, re-serialized: same fields and values
    assert _file_records(log) == collector.records()


def test_a_stalled_collector_never_costs_a_local_record(tmp_path: Path) -> None:
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)  # accepts, never answers
    stream, log, remote = _file_and_remote(
        tmp_path,
        f"http://127.0.0.1:{blocker.getsockname()[1]}/a",
        batch_max_records=4,
        buffer_max_records=6,
        flush_interval=0.01,
    )
    remote.start()
    try:
        for i in range(60):  # far beyond the 6-record buffer: the remote copy drops
            stream.call(f"tool_{i:02d}")
        assert stream.unavailable
        assert [r["tool"] for r in _file_records(log)] == [f"tool_{i:02d}" for i in range(60)]
    finally:
        remote.close()
        blocker.close()


def test_a_failing_local_file_still_ships_the_record(tmp_path: Path) -> None:
    with _Collector() as collector:
        remote = RemoteSink(
            RemoteConfig(url=f"http://127.0.0.1:{collector.port}/a", plaintext=True),
            start=False,
        )
        stream = AuditStream(
            sink=FileSink(str(tmp_path / "no-such-dir" / "a.jsonl")), remote_copy=remote, calls=True
        )
        stream.call("tool_a")
        assert stream.unavailable  # the file fault is reported, as for the file sink
        assert remote.sender.pump() is True
    assert [r["tool"] for r in collector.records()] == ["tool_a"]


def test_negative_control_remote_only_outage_keeps_nothing_locally(tmp_path: Path) -> None:
    """Without the file the same outage loses the records: the local file is what
    protects them (this is the behaviour S1 removes for the configured file)."""
    with _Collector() as down:
        port = down.port
    remote = RemoteSink(
        RemoteConfig(url=f"http://127.0.0.1:{port}/a", plaintext=True, max_attempts=1),
        start=False,
        sleep=lambda _s: None,
    )
    stream = AuditStream(sink=remote, calls=True)
    for i in range(10):
        stream.call(f"tool_{i}")
    assert remote.sender.pump() is False
    assert remote.sender.buffered() == 0  # the batch is gone, only its count remains
    assert remote.sender._pending["attempts_exhausted"].count == 10
    assert list(tmp_path.iterdir()) == []


# ================================================= S2: a count-based stall signal
def test_stall_signal_counts_records_behind_the_in_flight_batch() -> None:
    sender = RemoteSender(
        RemoteConfig(url="http://127.0.0.1:9/a", plaintext=True, batch_max_records=5)
    )
    release = threading.Event()
    sender._send = lambda _batch: (release.wait(), "acked")[1]  # type: ignore[method-assign]
    sender.emit(_record())
    worker = threading.Thread(target=sender.pump)
    worker.start()
    try:
        assert _wait(lambda: sender._inflight == 1)
        for _ in range(4):  # 4 behind the in-flight batch: a full batch is not yet waiting
            sender.emit(_record())
        assert not sender.failing
        sender.emit(_record())  # the 5th: a full second batch is waiting
        assert sender.failing and sender.notice == AUDIT_UNAVAILABLE
        assert sender.buffered() == 6  # far below the buffer limit
    finally:
        release.set()
        worker.join()
    assert not sender.failing  # the acknowledgment clears it like any failing state
    assert sender.buffered() == 0  # the stalled batch and everything behind it went out


def test_stall_signal_needs_a_batch_in_flight() -> None:
    sender = RemoteSender(
        RemoteConfig(url="http://127.0.0.1:9/a", plaintext=True, batch_max_records=3)
    )
    for _ in range(50):  # queued while nothing is being sent: ordinary backlog
        sender.emit(_record())
    assert not sender.failing


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_a_silent_collector_or_stalled_handshake_is_flagged_before_the_buffer_fills(
    scheme: str,
) -> None:
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)  # accepts the connection and never writes (no HTTP, no TLS reply)
    sink = RemoteSink(
        RemoteConfig(
            url=f"{scheme}://127.0.0.1:{blocker.getsockname()[1]}/a",
            plaintext=scheme == "http",
            batch_max_records=5,
            buffer_max_records=1000,
            flush_interval=0.01,
        )
    )
    stream = AuditStream(sink=sink, calls=True)
    try:
        stream.call("first")
        assert _wait(lambda: sink.sender._inflight == 1)
        assert not stream.unavailable
        for i in range(5):
            stream.call(f"t{i}")
        assert stream.unavailable and sink.sender.buffered() == 6
        assert "audit_remote_dropped" not in sink.sender.buffered_events()  # nothing dropped
    finally:
        sink.close()
        blocker.close()


# ======================================================== S3: the shutdown trace
def test_close_logs_the_count_of_discarded_records_and_no_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = RemoteSink(
        RemoteConfig(url=f"http://127.0.0.1:9/{PATH_MARK}", plaintext=True), start=False
    )
    stream = AuditStream(sink=sink, calls=True)
    for i in range(3):
        stream.call(f"secret-looking-tool-{i}")
    with caplog.at_level(logging.INFO, logger="unifi_fabric.audit_remote"):
        sink.close()
        sink.close()  # once only
    messages = [r.getMessage() for r in caplog.records if "discarded" in r.getMessage()]
    assert messages == [
        "audit remote sink http://127.0.0.1:9 closed with 3 unacknowledged record(s) discarded"
    ]
    assert "secret-looking-tool" not in caplog.text and PATH_MARK not in caplog.text


def test_close_with_nothing_buffered_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    sink = RemoteSink(RemoteConfig(url="http://127.0.0.1:9/a", plaintext=True), start=False)
    with caplog.at_level(logging.INFO, logger="unifi_fabric.audit_remote"):
        sink.close()
    assert "discarded" not in caplog.text


# ================================================ S4: the three missing transport tests
def test_an_encrypted_client_key_fails_the_attempt_without_a_prompt(
    certs: _Certs, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import secrets as pysecrets

    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(certs.client_key.read_bytes(), password=None)
    passphrase = pysecrets.token_hex(8).encode()  # built at runtime: no secret literal
    encrypted = tmp_path / "client-encrypted.key"
    encrypted.write_bytes(
        key.private_bytes(  # type: ignore[union-attr]
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        )
    )
    attempts: list[dict[str, Any]] = []
    with _Collector(_server_ctx(certs, mtls=True)) as collector:
        sender = _sender(
            RemoteConfig(
                url=f"https://localhost:{collector.port}/a",
                ca_file=str(certs.ca),
                cert_file=str(certs.client_cert),
                key_file=str(encrypted),
                max_attempts=2,
            ),
            attempts,
        )
        sender.emit(_record())
        with caplog.at_level(logging.DEBUG, logger="unifi_fabric.audit_remote"):
            assert sender.pump() is False  # returns: no password prompt, no hang
    assert collector.requests == []
    assert [a["status"] for a in attempts] == [None, None]
    assert {a["error"] for a in attempts} <= {"SSLError", "ValueError"}
    assert sender.notice == AUDIT_UNAVAILABLE
    assert str(encrypted) not in caplog.text and passphrase.decode() not in caplog.text


def test_a_tls_12_only_collector_is_refused_and_nothing_is_sent(
    certs: _Certs, caplog: pytest.LogCaptureFixture
) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(certs.server_cert), str(certs.server_key))
    attempts: list[dict[str, Any]] = []
    with _Collector(ctx) as collector:
        sender = _sender(
            RemoteConfig(
                url=f"https://localhost:{collector.port}/a", ca_file=str(certs.ca), max_attempts=2
            ),
            attempts,
        )
        sender.emit(_record())
        assert sender.pump() is False
    assert collector.requests == []  # never downgraded to TLS 1.2
    assert [a["status"] for a in attempts] == [None, None]
    assert {a["error"] for a in attempts} == {"SSLError"}
    assert sender._pending["attempts_exhausted"].count == 1  # counted, nothing sent


def test_a_lone_surrogate_is_kept_locally_and_counted_remotely(tmp_path: Path) -> None:
    """F1/F2 behaviour: a caller-influenced field with a lone surrogate cannot be strict
    UTF-8 JSON, so the remote copy is dropped (count only, reason ``unserializable``, the
    content never leaves); the local file still holds the record."""
    marker = "\ud83d"  # one lone high surrogate
    with _Collector() as collector:
        stream, log, remote = _file_and_remote(tmp_path, f"http://127.0.0.1:{collector.port}/a")
        stream.call("tool_a")
        stream.call("tool_" + marker + "_b")
        stream.call("tool_c")
        assert remote.sender.pump() is True
    assert [r["tool"] for r in collector.records() if r["event"] == "call"] == ["tool_a", "tool_c"]
    dropped = [r for r in collector.records() if r["event"] == "audit_remote_dropped"]
    assert [(d["reason"], d["dropped_count"]) for d in dropped] == [("unserializable", 1)]
    assert "tool_" + marker not in collector.requests[0]["body"].decode("utf-8", "replace")
    on_disk = log.read_bytes().decode("ascii")  # backslashreplace: pure ASCII
    assert "tool_\\ud83d_b" in on_disk and on_disk.count("\n") == 3


# ===================================================================== D1/D2 (docs)
def test_generated_reference_labels_the_numeric_remote_settings() -> None:
    root = Path(__file__).resolve().parent.parent
    text = (root / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    rows = dict(
        re.findall(r"^\| `(UNIFI_AUDIT_REMOTE_[A-Z_]+)` \| `[^`]*` \| ([^|]+) \|", text, re.M)
    )
    for name in (
        "MAX_ATTEMPTS",
        "BATCH_MAX_RECORDS",
        "BATCH_MAX_BYTES",
        "BUFFER_MAX_RECORDS",
        "BUFFER_MAX_BYTES",
    ):
        assert rows[f"UNIFI_AUDIT_REMOTE_{name}"].strip() == "integer, 1 or more"
    for name in ("RETRY_BACKOFF_SECONDS", "FLUSH_INTERVAL_SECONDS"):
        assert rows[f"UNIFI_AUDIT_REMOTE_{name}"].strip() == "number above 0"
    assert "audit HMAC key (Code Mode argument audit and pseudonymised audit identifiers)" in text
