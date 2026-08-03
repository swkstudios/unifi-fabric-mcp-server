"""Real-socket mutual-TLS tests for the ``tls_mode='mtls'`` client-cert path (Phase 4).

These prove ``build_uvicorn_config``'s mTLS ssl kwargs (``ssl_ca_certs`` +
``ssl_cert_reqs=CERT_REQUIRED``) over a REAL TLS socket:

* a ``trustme`` in-memory CA issues a server cert/key for ``127.0.0.1`` AND a
  client cert signed by that same CA;
* a separate *foreign* CA issues an untrusted client cert;
* ``uvicorn`` serves a minimal FastMCP streamable-http app on an ephemeral
  ``127.0.0.1`` port using the mTLS kwargs from ``build_uvicorn_config`` (so the
  server presents its cert AND requires + verifies a client cert against the CA);
* a client presenting a **valid** client cert (and trusting the server CA)
  completes the TLS handshake AND a real MCP ``initialize`` (HTTP 200);
* a client presenting **no** client cert is rejected — the connection never
  carries an MCP response;
* a client presenting a **foreign-CA** client cert is rejected likewise.

The two reject cases are the security-load-bearing assertions. Because a TLS 1.3
client-cert rejection can surface either at the handshake or at the first
application read (the server sends an alert and drops the connection), each
reject test asserts a broad ``httpx.TransportError`` (the umbrella over
``ReadError`` / ``RemoteProtocolError`` / ``ConnectError``) AND runs a valid-cert
control request against the *same* live server that returns 200 — proving the
refusal is cert-driven, not a server that simply never came up.

Scope: mTLS here is a **transport-level identity / network boundary** only. The
client-cert subject is deliberately NOT bound to any application identity — that
composes with, and does not replace, app-layer auth (bearer / oauth / none).
These tests therefore assert handshake admission, not who the certificate claims
to be.

Everything binds ``127.0.0.1`` with in-memory CAs and no external network, so
these run in CI by default. They are tagged ``@pytest.mark.tls`` for selection
only — there is no runtime skip (unlike the live-API integration tests), so the
no-cert and untrusted-cert reject halves always execute.
"""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import trustme
import uvicorn
from fastmcp import FastMCP

from unifi_fabric.config import MCPTransportSettings
from unifi_fabric.server import build_uvicorn_config

HTTP = "streamable-http"
_READY_TIMEOUT_S = 15.0
_SHUTDOWN_TIMEOUT_S = 15.0
# Bounded so a reject that (wrongly) hangs fails fast instead of stalling CI.
_CLIENT_TIMEOUT_S = 10.0


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Isolate every test from ambient MCP_*/FASTMCP_* configuration."""
    for k in list(os.environ):
        if k.startswith(("MCP_", "FASTMCP_")):
            monkeypatch.delenv(k, raising=False)
    yield


# ---------------------------------------------------------------------------
# trustme cert material (in-memory CAs — no files committed, no network)
# ---------------------------------------------------------------------------


class _MtlsCertBundle:
    """A CA that signs both the server cert and a valid client cert, plus a
    foreign CA that signs an untrusted client cert.

    All PEMs are written under a per-test ``tmp_path`` and never committed; the
    private keys never leave the test process's temp dir.
    """

    def __init__(self, tmp: Path) -> None:
        # The trusted CA: verifies the server cert (client side) AND the client
        # cert (server side, via ssl_ca_certs). One CA, both directions.
        self.ca = trustme.CA()
        self.ca_pem = tmp / "ca.pem"
        self.ca.cert_pem.write_to_path(str(self.ca_pem))

        server_cert = self.ca.issue_cert("127.0.0.1")
        self.server_certfile = tmp / "server-cert.pem"
        self.server_keyfile = tmp / "server-key.pem"
        server_cert.cert_chain_pems[0].write_to_path(str(self.server_certfile))
        server_cert.private_key_pem.write_to_path(str(self.server_keyfile))

        # A valid client cert chaining to the trusted CA. Its identity is
        # cosmetic — mTLS here is transport admission, not app identity (#3).
        client_cert = self.ca.issue_cert("client.mtls.test")
        self.client_certfile = tmp / "client-cert.pem"
        self.client_keyfile = tmp / "client-key.pem"
        client_cert.cert_chain_pems[0].write_to_path(str(self.client_certfile))
        client_cert.private_key_pem.write_to_path(str(self.client_keyfile))

        # A foreign CA + client cert the server's CA bundle does NOT trust —
        # used to prove untrusted client certs are actually rejected.
        self.foreign_ca = trustme.CA()
        foreign_client_cert = self.foreign_ca.issue_cert("client.mtls.test")
        self.foreign_client_certfile = tmp / "foreign-client-cert.pem"
        self.foreign_client_keyfile = tmp / "foreign-client-key.pem"
        foreign_client_cert.cert_chain_pems[0].write_to_path(str(self.foreign_client_certfile))
        foreign_client_cert.private_key_pem.write_to_path(str(self.foreign_client_keyfile))


@pytest.fixture
def certs(tmp_path) -> _MtlsCertBundle:
    return _MtlsCertBundle(tmp_path)


def _free_localhost_socket() -> socket.socket:
    """Bind an ephemeral 127.0.0.1 port and hand the live socket to uvicorn.

    Binding ourselves (rather than letting uvicorn pick a port) lets us read the
    real port via ``getsockname`` with no TOCTOU race against a separate probe.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


@contextlib.contextmanager
def _serve_mtls(uvicorn_config: dict) -> Iterator[str]:
    """Run a minimal FastMCP streamable-http app over mTLS in a background thread.

    Yields the base ``https://127.0.0.1:<port>/mcp`` URL. Guarantees the server
    is bound before yielding and is shut down + joined on exit (no socket leak).
    """
    mcp = FastMCP("mtls-socket-test")

    @mcp.tool
    def ping_tool() -> str:
        return "pong"

    sock = _free_localhost_socket()
    port = sock.getsockname()[1]

    config = uvicorn.Config(mcp.http_app(), log_level="warning", **uvicorn_config)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()

    try:
        deadline = time.monotonic() + _READY_TIMEOUT_S
        while not server.started:
            if time.monotonic() > deadline:
                raise TimeoutError("uvicorn mTLS server did not become ready in time")
            time.sleep(0.05)
        yield f"https://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=_SHUTDOWN_TIMEOUT_S)
        with contextlib.suppress(OSError):
            sock.close()


def _mtls_settings(monkeypatch, certs: _MtlsCertBundle) -> MCPTransportSettings:
    """Resolve mTLS transport settings (server cert/key + client CA bundle).

    ``MCP_TLS_CERT_REQS`` is left unset so it defaults to CERT_REQUIRED — the
    fail-closed posture build_uvicorn_config emits for mtls.
    """
    monkeypatch.setenv("FASTMCP_TRANSPORT", HTTP)
    monkeypatch.setenv("MCP_TLS_MODE", "mtls")
    monkeypatch.setenv("MCP_TLS_CERTFILE", str(certs.server_certfile))
    monkeypatch.setenv("MCP_TLS_KEYFILE", str(certs.server_keyfile))
    monkeypatch.setenv("MCP_TLS_CA_CERTS", str(certs.ca_pem))
    return MCPTransportSettings()


def _client_ctx(
    ca_pem: Path,
    *,
    client_cert: Path | None = None,
    client_key: Path | None = None,
) -> ssl.SSLContext:
    """A verifying client TLS context trusting *only* ``ca_pem`` for the server,
    optionally presenting a client certificate.

    Loading the client cert into the SSLContext (rather than httpx's deprecated
    ``cert=(cert, key)`` tuple) keeps trust scoped to the in-memory CA while
    still presenting the client identity — equivalent to ``cert=(...)`` but
    composed into the same verifying context, consistent with the https tests.
    """
    ctx = ssl.create_default_context(cafile=str(ca_pem))
    if client_cert is not None and client_key is not None:
        ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


def _mcp_initialize_request() -> tuple[dict, dict]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mtls-socket-test", "version": "0"},
        },
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    return payload, headers


def _post_initialize_ok(url: str, ctx: ssl.SSLContext) -> httpx.Response:
    """Drive a real MCP ``initialize`` with the given client context (control/happy path)."""
    payload, headers = _mcp_initialize_request()
    with httpx.Client(verify=ctx, timeout=_CLIENT_TIMEOUT_S) as client:
        return client.post(url, json=payload, headers=headers)


# ---------------------------------------------------------------------------
# Unit: the mtls uvicorn config actually carries the CA bundle + CERT_REQUIRED
# ---------------------------------------------------------------------------


def test_mtls_uvicorn_config_wires_ca_and_required(monkeypatch, certs):
    """build_uvicorn_config(mtls) emits the client CA bundle and CERT_REQUIRED."""
    cfg = _mtls_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)
    assert uvicorn_config is not None
    assert uvicorn_config["ssl_ca_certs"] == str(certs.ca_pem)
    assert uvicorn_config["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert uvicorn_config["ssl_certfile"] == str(certs.server_certfile)


# ---------------------------------------------------------------------------
# Real-socket handshake — success path (valid client cert) + MCP request
# ---------------------------------------------------------------------------


@pytest.mark.tls
def test_mtls_valid_client_cert_handshake_and_mcp_request_succeed(monkeypatch, certs):
    """Valid client cert: mutual TLS handshake completes AND a real MCP request returns."""
    cfg = _mtls_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)
    assert uvicorn_config is not None

    with _serve_mtls(uvicorn_config) as url:
        ctx = _client_ctx(
            certs.ca_pem,
            client_cert=certs.client_certfile,
            client_key=certs.client_keyfile,
        )
        resp = _post_initialize_ok(url, ctx)

    assert resp.status_code == 200
    # Proves the MCP layer actually answered initialize (not just a raw socket).
    assert "protocolVersion" in resp.text
    assert '"result"' in resp.text


# ---------------------------------------------------------------------------
# Real-socket handshake — reject paths. SECURITY-LOAD-BEARING (must execute).
# ---------------------------------------------------------------------------


@pytest.mark.tls
def test_mtls_no_client_cert_is_rejected(monkeypatch, certs):
    """No client cert: the request must FAIL — CERT_REQUIRED admits no anonymous client.

    A same-server control request *with* a valid client cert returns 200, proving
    the rejection is the missing client certificate and not a server that never
    started (which would also raise here).
    """
    cfg = _mtls_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)

    with _serve_mtls(uvicorn_config) as url:
        # Control: server is genuinely up and serving over mTLS.
        ok = _post_initialize_ok(
            url,
            _client_ctx(
                certs.ca_pem,
                client_cert=certs.client_certfile,
                client_key=certs.client_keyfile,
            ),
        )
        assert ok.status_code == 200

        # Security assertion: a client presenting NO certificate is refused.
        no_cert_ctx = _client_ctx(certs.ca_pem)  # trusts server CA, presents nothing
        payload, headers = _mcp_initialize_request()
        with httpx.Client(verify=no_cert_ctx, timeout=_CLIENT_TIMEOUT_S) as client:
            with pytest.raises(httpx.TransportError):
                client.post(url, json=payload, headers=headers)


@pytest.mark.tls
def test_mtls_untrusted_client_cert_is_rejected(monkeypatch, certs):
    """Foreign-CA client cert: the request must FAIL — it does not chain to the CA bundle.

    As above, a same-server control request with a valid client cert returns 200,
    so the rejection is the untrusted client certificate, not a dead server.
    """
    cfg = _mtls_settings(monkeypatch, certs)
    uvicorn_config = build_uvicorn_config(cfg)

    with _serve_mtls(uvicorn_config) as url:
        # Control: server is genuinely up and serving over mTLS.
        ok = _post_initialize_ok(
            url,
            _client_ctx(
                certs.ca_pem,
                client_cert=certs.client_certfile,
                client_key=certs.client_keyfile,
            ),
        )
        assert ok.status_code == 200

        # Security assertion: a client whose cert is signed by a foreign CA is
        # refused — it trusts the server CA (so the server cert verifies) but its
        # own cert does not chain to the server's MCP_TLS_CA_CERTS bundle.
        foreign_ctx = _client_ctx(
            certs.ca_pem,
            client_cert=certs.foreign_client_certfile,
            client_key=certs.foreign_client_keyfile,
        )
        payload, headers = _mcp_initialize_request()
        with httpx.Client(verify=foreign_ctx, timeout=_CLIENT_TIMEOUT_S) as client:
            with pytest.raises(httpx.TransportError):
                client.post(url, json=payload, headers=headers)
