"""Focused proofs for the test-harness CodeQL fixes (alerts on the public scan:
py/http-response-splitting and py/insecure-protocol in tests/proxy_container/driver.py,
py/weak-sensitive-data-hashing in tests/upstream_harness.py)."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import ssl
from pathlib import Path

from tests import upstream_harness

DRIVER = Path(__file__).resolve().parent / "proxy_container" / "driver.py"


def _driver():
    spec = importlib.util.spec_from_file_location("proxy_container_driver", DRIVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Response:
    status = 200

    def getheaders(self):
        return [
            ("Content-Type", "application/json"),
            ("X-Split", "ok\r\nSet-Cookie: injected=1"),
            ("X-Bare-LF", "a\nb"),
            ("Mcp-Session-Id", "abc"),
        ]

    def read(self):
        return b"{}"


class _Conn:
    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, *_args, **_kwargs):
        pass

    def getresponse(self):
        return _Response()

    def close(self):
        pass


def test_proxy_drops_forwarded_header_values_with_cr_or_lf(monkeypatch):
    driver = _driver()
    monkeypatch.setattr(driver.http.client, "HTTPConnection", _Conn)
    handler = driver.Handler.__new__(driver.Handler)
    handler.rfile = io.BytesIO(b"{}")
    handler.wfile = io.BytesIO()
    handler.path = "/mcp"
    handler.headers = {"Content-Length": "2", "Host": driver.HOST}
    sent: list[tuple[str, str]] = []
    handler.send_response = lambda status: None
    handler.send_header = lambda key, value: sent.append((key, value))
    handler.end_headers = lambda: None
    handler.do_POST()
    names = [key for key, _ in sent]
    assert "X-Split" not in names and "X-Bare-LF" not in names
    assert ("Mcp-Session-Id", "abc") in sent and ("Content-Length", "2") in sent
    assert all("\r" not in v and "\n" not in v for _, v in sent)


def test_tls_proxy_requires_tls_1_2_or_newer(monkeypatch):
    driver = _driver()
    contexts: list[_Context] = []

    class _Context:
        def __init__(self, protocol):
            self.protocol = protocol
            self.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            contexts.append(self)

        def load_cert_chain(self, *_args, **_kwargs):
            pass

        def wrap_socket(self, sock, **_kwargs):
            return sock

    class _Server:
        def __init__(self, *_args):
            self.socket = object()

        def serve_forever(self):
            pass

    monkeypatch.setattr(driver.ssl, "SSLContext", _Context)
    monkeypatch.setattr(driver, "ThreadingHTTPServer", _Server)
    driver.start_server(0, tls=True)
    (context,) = contexts
    assert context.protocol == ssl.PROTOCOL_TLS_SERVER
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_key_probe_tag_is_a_keyed_per_run_fingerprint():
    key = "probe-key-value"
    tag = upstream_harness.key_probe_tag(key)
    assert tag == upstream_harness.key_probe_tag(key)
    assert tag != upstream_harness.key_probe_tag(key + "x")
    assert len(tag) == 16
    assert tag != hashlib.sha256(key.encode()).hexdigest()[:16]
