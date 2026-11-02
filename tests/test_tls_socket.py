"""Real-socket HTTPS tests for the ``tls_mode='https'`` server-cert path (Phase 3).

These exercise ``build_uvicorn_config``'s ssl kwargs over a REAL TLS socket:

* a ``trustme`` in-memory CA issues a server cert/key for ``127.0.0.1``;
* ``uvicorn`` serves a minimal FastMCP streamable-http app on an ephemeral
  ``127.0.0.1`` port using the ssl kwargs produced by ``build_uvicorn_config``;
* an httpx client trusting the right CA completes the TLS handshake AND a real
  MCP ``initialize`` request (HTTP 200 + JSON-RPC result);
* an httpx client trusting the WRONG CA fails the handshake — this reject is the
  security-load-bearing assertion and must execute, never skip.

Everything binds ``127.0.0.1`` with an in-memory CA and no external network, so
these run in CI by default. They are tagged ``@pytest.mark.tls`` for selection
only — there is no runtime skip (unlike the live-API integration tests), so the
wrong-CA reject half always runs.

Also covers the ``tls_cert_reqs`` selector wiring (unit-level): the right
``ssl.CERT_*`` constant lands in the uvicorn config per mode, and the fail-closed
validator rejects ``tls_cert_reqs='none'`` under mTLS.
"""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import trustme
import uvicorn
from fastmcp import FastMCP
from pydantic import ValidationError

from unifi_fabric.config import MCPTransportSettings
from unifi_fabric.server import build_uvicorn_config

HTTP = "streamable-http"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Isolate every test from ambient MCP_*/FASTMCP_* configuration."""
    for k in list(os.environ):
        if k.startswith(("MCP_", "FASTMCP_")):
            monkeypatch.delenv(k, raising=False)
    yield


# ---------------------------------------------------------------------------
# trustme cert material (in-memory CA — no files committed, no network)
# ---------------------------------------------------------------------------


class _CertBundle:
    def __init__(self, tmp: Path) -> None:
        self.ca = trustme.CA()
        server_cert = self.ca.issue_cert("127.0.0.1")
        self.certfile = tmp / "server-cert.pem"
        self.keyfile = tmp / "server-key.pem"
        self.ca_pem = tmp / "ca.pem"
        server_cert.cert_chain_pems[0].write_to_path(str(self.certfile))
        server_cert.private_key_pem.write_to_path(str(self.keyfile))
        self.ca.cert_pem.write_to_path(str(self.ca_pem))

        # An unrelated CA the server cert does NOT chain to — used to prove the
        # handshake is actually verified (not just transported).
        self.wrong_ca = trustme.CA()
        self.wrong_ca_pem = tmp / "wrong-ca.pem"
        self.wrong_ca.cert_pem.write_to_path(str(self.wrong_ca_pem))


@pytest.fixture
def certs(tmp_path) -> _CertBundle:
    return _CertBundle(tmp_path)


def _free_localhost_socket() -> socket.socket:
    """Bind an ephemeral 127.0.0.1 port and hand the live socket to uvicorn.

    Binding ourselves (rather than letting uvicorn pick a port) lets us read the
    real port via ``getsockname`` with no TOCTOU race against a separate probe. The
    socket listens at once and does not set ``SO_REUSEADDR``, so no other socket can
    bind the same port while it waits for uvicorn to start serving on it.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


@contextlib.contextmanager
def _serve_tls(uvicorn_config: dict) -> Iterator[str]:
    """Run a minimal FastMCP streamable-http app over TLS in a background thread.

    Yields the base ``https://127.0.0.1:<port>/mcp`` URL. Guarantees the server
    is bound before yielding and is shut down + joined on exit (no socket leak).
    """
    mcp = FastMCP("tls-socket-test")

    @mcp.tool
    def ping_tool() -> str:
        return "pong"

    sock = _free_localhost_socket()
    port = sock.getsockname()[1]

    config = uvicorn.Config(mcp.http_app(), log_level="warning", **uvicorn_config)
    ready = threading.Event()
    failures: list[BaseException] = []

    class CompletionServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            ready.set()

    server = CompletionServer(config)

    def run_server():
        try:
            server.run(sockets=[sock])
        except BaseException as exc:  # Thread failures must reach the test, including SystemExit.
            failures.append(exc)
        finally:
            ready.set()  # A failed startup also releases the test to report the failure.

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    try:
        ready.wait()
        if failures:
            raise RuntimeError("TLS server failed during startup") from failures[0]
        if not server.started:
            raise RuntimeError("TLS server exited before completing startup")
        yield f"https://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join()
        with contextlib.suppress(OSError):
            sock.close()
        if failures:
            raise RuntimeError("TLS server thread failed") from failures[0]


def _https_settings(monkeypatch, certs: _CertBundle) -> MCPTransportSettings:
    monkeypatch.setenv("FASTMCP_TRANSPORT", HTTP)
    monkeypatch.setenv("MCP_TLS_MODE", "https")
    monkeypatch.setenv("MCP_TLS_CERTFILE", str(certs.certfile))
    monkeypatch.setenv("MCP_TLS_KEYFILE", str(certs.keyfile))
    return MCPTransportSettings()


def _client_ssl_context(ca_pem: Path) -> ssl.SSLContext:
    """A verifying TLS client context that trusts *only* ``ca_pem``.

    Passing an explicit context (rather than ``verify=<path str>``, which httpx
    deprecates) keeps the client on full certificate verification while scoping
    trust to the in-memory CA — so the wrong-CA case is a genuine verification
    failure, not a disabled check.
    """
    return ssl.create_default_context(cafile=str(ca_pem))


def _mcp_initialize_request() -> tuple[dict, dict]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "tls-socket-test", "version": "0"},
        },
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    return payload, headers


# ---------------------------------------------------------------------------
# Real-socket handshake — success path (right CA) + MCP request
# ---------------------------------------------------------------------------


@pytest.mark.tls
def test_https_handshake_and_mcp_request_succeed(monkeypatch, certs):
    """Right-CA client: TLS handshake completes AND a real MCP request returns."""
    cfg = _https_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)
    assert uvicorn_config is not None
    payload, headers = _mcp_initialize_request()

    with _serve_tls(uvicorn_config) as url:
        with httpx.Client(verify=_client_ssl_context(certs.ca_pem), timeout=None) as client:  # noqa: S113 - wait for local socket completion
            resp = client.post(url, json=payload, headers=headers)

    assert resp.status_code == 200
    # Proves the MCP layer actually answered the initialize (not just a raw socket).
    assert "protocolVersion" in resp.text
    assert '"result"' in resp.text


# ---------------------------------------------------------------------------
# Real-socket handshake — reject path (wrong CA). SECURITY-LOAD-BEARING.
# ---------------------------------------------------------------------------


@pytest.mark.tls
def test_https_wrong_ca_handshake_is_rejected(monkeypatch, certs):
    """Wrong-CA client: the TLS handshake must FAIL (cert verification rejects)."""
    cfg = _https_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)
    payload, headers = _mcp_initialize_request()

    with _serve_tls(uvicorn_config) as url:
        wrong = _client_ssl_context(certs.wrong_ca_pem)
        with httpx.Client(verify=wrong, timeout=None) as client:  # noqa: S113 - wait for local socket completion
            with pytest.raises(httpx.ConnectError) as exc:
                client.post(url, json=payload, headers=headers)

    # The rejection must be a certificate-verification failure, not a fluke
    # (e.g. connection refused). Assert on the underlying SSL reason.
    assert "CERTIFICATE_VERIFY_FAILED" in str(exc.value)


@pytest.mark.tls
def test_https_default_system_trust_rejects_self_signed(monkeypatch, certs):
    """A client using default system trust (verify=True) also rejects the cert.

    Defence-in-depth: the in-memory CA is not in any system trust store, so a
    stock verifying client must fail too — the success path is not an artefact of
    disabled verification somewhere in the stack.
    """
    cfg = _https_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)
    payload, headers = _mcp_initialize_request()

    with _serve_tls(uvicorn_config) as url:
        with httpx.Client(verify=True, timeout=None) as client:  # noqa: S113 - wait for local socket completion
            with pytest.raises(httpx.ConnectError) as exc:
                client.post(url, json=payload, headers=headers)

    assert "CERTIFICATE_VERIFY_FAILED" in str(exc.value)


# ---------------------------------------------------------------------------
# tls_cert_reqs selector wiring (unit) — the right ssl.CERT_* lands per mode
# ---------------------------------------------------------------------------


def _settings(monkeypatch, **env: str) -> MCPTransportSettings:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return MCPTransportSettings()


def test_https_cert_reqs_defaults_to_cert_none(monkeypatch):
    """https mode requests no client cert: ssl_cert_reqs is omitted (CERT_NONE).

    uvicorn defaults an unset ``ssl_cert_reqs`` to ``ssl.CERT_NONE``; https has no
    client CA so the server must not demand a client certificate.
    """
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="https",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out is not None
    assert "ssl_cert_reqs" not in out
    assert "ssl_ca_certs" not in out


def test_mtls_cert_reqs_default_required(monkeypatch):
    """mTLS with no explicit selector defaults to CERT_REQUIRED (fail-closed)."""
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="mtls",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        MCP_TLS_CA_CERTS="/c/ca.pem",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out is not None
    assert out["ssl_cert_reqs"] == ssl.CERT_REQUIRED


def test_mtls_cert_reqs_required_explicit(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="mtls",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        MCP_TLS_CA_CERTS="/c/ca.pem",
        MCP_TLS_CERT_REQS="required",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out is not None
    assert out["ssl_cert_reqs"] == ssl.CERT_REQUIRED


def test_mtls_cert_reqs_optional_maps(monkeypatch):
    """The selector is live: 'optional' maps to ssl.CERT_OPTIONAL, not hard-coded."""
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="mtls",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        MCP_TLS_CA_CERTS="/c/ca.pem",
        MCP_TLS_CERT_REQS="optional",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out is not None
    assert out["ssl_cert_reqs"] == ssl.CERT_OPTIONAL


def test_mtls_cert_reqs_none_rejected(monkeypatch):
    """Fail-closed: tls_cert_reqs='none' under mTLS is rejected at construction.

    mTLS exists to verify client certificates; CERT_NONE would silently disable
    that, so the selector combination must raise rather than degrade.
    """
    with pytest.raises(ValidationError) as exc:
        _settings(
            monkeypatch,
            MCP_TLS_MODE="mtls",
            MCP_TLS_CERTFILE="/c/cert.pem",
            MCP_TLS_KEYFILE="/c/key.pem",
            MCP_TLS_CA_CERTS="/c/ca.pem",
            MCP_TLS_CERT_REQS="none",
            FASTMCP_TRANSPORT=HTTP,
        )
    assert "MCP_TLS_CERT_REQS" in str(exc.value)


def test_https_startup_failure_is_reported_after_thread_completion(monkeypatch, certs):
    async def failed_startup(self, sockets=None):
        raise RuntimeError("synthetic startup failure")

    monkeypatch.setattr(uvicorn.Server, "startup", failed_startup)
    config = build_uvicorn_config(_https_settings(monkeypatch, certs))
    with pytest.raises(RuntimeError, match="TLS server thread failed") as exc:
        with _serve_tls(config):
            pytest.fail("a server that failed startup must never be yielded")
    assert str(exc.value.__cause__) == "synthetic startup failure"


@pytest.mark.parametrize(
    ("filename", "case", "fence", "endpoint"),
    [
        ("TLS.md", "docs-tls-3", "sh", "https://127.0.0.1:3000/mcp"),
        ("TLS.md", "docs-tls-7", "sh", "https://127.0.0.1:3000/mcp"),
        ("TLS.md", "docs-tls-11", "bash", "https://localhost:3000/mcp"),
        ("CONFIGURATION.md", "docs-configuration-4", "bash", "http://localhost:3000/sse"),
        ("AUTH-OAUTH.md", "docs-auth-oauth-12", "bash", "http://127.0.0.1:8000/sse"),
    ],
)
def test_documented_transport_curl_probes_observe_progress_without_deadlines(
    filename, case, fence, endpoint
):
    text = (Path(__file__).resolve().parents[1] / "docs" / filename).read_text()
    example = text.split(f"<!-- install-case: {case} ", 1)[1].split(f"```{fence}\n", 1)[1]
    example = example.split("```", 1)[0]
    assert "--max-time" not in example
    assert "--connect-timeout" not in example
    assert "Keep the probe bounded" not in example
    assert endpoint in example
    if filename == "TLS.md":
        assert "--cacert" in example
    else:
        # SSE is a stream: expose headers/events as they arrive instead of waiting
        # for curl's exit-time status formatter or an artificial disconnect.
        assert "--include --no-buffer" in example
        assert "--write-out" not in example and "-w " not in example
    if case in {"docs-tls-7", "docs-tls-11"}:
        assert "--cert client-cert.pem --key client-key.pem" in example
    if filename == "AUTH-OAUTH.md":
        assert "Authorization: Bearer ${TOKEN}" in example
