"""Request-head bounds precede every application/auth logger."""

import asyncio
import hashlib
import logging
import socket

import httpx
import pytest
import uvicorn

from unifi_fabric.access_log import B_HEADERS, AccessLogMiddleware
from unifi_fabric.config import MCPTransportSettings
from unifi_fabric.server import FabricMCP, build_uvicorn_config


def scope(target, headers=()):
    path, _, query = target.partition(b"?")
    return {
        "type": "http",
        "raw_path": path,
        "path": path.decode("ascii"),
        "query_string": query,
        "headers": list(headers),
        "method": "GET",
        "client": ("127.0.0.1", 12345),
        "http_version": "1.1",
    }


async def exercise(target, headers=()):
    called = []
    messages = []

    async def app(scope, receive, send):
        called.append(scope)
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b"not found"})

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    await AccessLogMiddleware(app)(scope(target, headers), receive, send)
    return called, messages


@pytest.mark.parametrize("size", [1023, 1024])
@pytest.mark.parametrize("query", [False, True])
async def test_at_bound_logs_path_and_masks_query(caplog, size, query):
    target = (b"/test?" if query else b"/") + b"q" * (size - (6 if query else 1))
    caplog.set_level(logging.INFO)
    called, messages = await exercise(target)
    assert called and messages[0]["status"] == 404
    (record,) = [r for r in caplog.records if r.name == "unifi_fabric.access"]
    expected = "/test?***" if query else target.decode()
    assert expected in record.getMessage()
    if query:
        assert target.decode() not in record.getMessage()
    assert '127.0.0.1:12345 - "GET ' in record.getMessage()
    assert 'HTTP/1.1" 404' in record.getMessage()


@pytest.mark.parametrize("size", [1025, 16384, 32768, 65536, 131072])
async def test_large_target_never_reaches_app_or_any_log(caplog, size):
    caplog.set_level(logging.DEBUG)
    sentinel = b"REJECTED_TARGET_SENTINEL"
    target = b"/" + sentinel + b"q" * (size - len(sentinel) - 1)
    called, messages = await exercise(target)
    assert not called
    assert messages[0]["status"] == 414
    assert messages[1]["body"] == b"Request target too large\n"
    digest = hashlib.sha256(target).hexdigest()[:16]
    assert f"<target withheld: {size} bytes sha256:{digest}>" in caplog.text
    for record in caplog.records:
        assert sentinel.decode() not in str(record.msg)
        assert sentinel.decode() not in repr(record.args)
        assert target.decode() not in record.getMessage()


@pytest.mark.parametrize("extra,expected", [(0, 404), (1, 431)])
async def test_header_block_boundary(caplog, extra, expected):
    caplog.set_level(logging.DEBUG)
    target = b"/HEADER_REJECT_TARGET"
    marker = b"HEADER_VALUE_SENTINEL"
    value = marker + b"x" * (B_HEADERS + extra - 7 - len(marker))
    called, messages = await exercise(target, [(b"x", value)])
    assert messages[0]["status"] == expected
    assert bool(called) == (expected == 404)
    if expected == 431:
        assert messages[1]["body"] == b"Request headers too large\n"
        assert "<target withheld:" in caplog.text
    for record in caplog.records:
        assert marker.decode() not in str(record.msg) + repr(record.args)
        if expected == 431:
            assert target.decode() not in str(record.msg) + repr(record.args)


async def test_in_bound_target_is_scrubbed_by_existing_record_factory(caplog, monkeypatch):
    from unifi_fabric import secret_scrub

    marker = "phase1-test-secret"
    monkeypatch.setattr(secret_scrub, "_provider", lambda: (marker,))
    caplog.set_level(logging.INFO)
    called, messages = await exercise(("/in-bound?token=" + marker).encode())
    assert called and messages[0]["status"] == 404
    assert "***" in caplog.text
    for record in caplog.records:
        assert marker not in str(record.msg) + repr(record.args)


async def test_non_http_passes_through_without_logging(caplog):
    calls = []

    async def app(scope, receive, send):
        calls.append(scope)

    await AccessLogMiddleware(app)({"type": "lifespan"}, None, None)
    assert calls and not caplog.records


@pytest.mark.parametrize("tls", ["none", "https", "mtls"])
def test_config_disables_uvicorn_access_log(tls, monkeypatch):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "http")
    options = {"tls_mode": tls}
    if tls != "none":
        options.update(tls_certfile="/synthetic/cert", tls_keyfile="/synthetic/key")
    if tls == "mtls":
        options.update(tls_ca_certs="/synthetic/ca")
    config = build_uvicorn_config(MCPTransportSettings(**options))
    assert config["access_log"] is False
    assert config["ws"] == "none"


@pytest.mark.parametrize("transport", ["http", "streamable-http", "sse"])
@pytest.mark.parametrize("direct", [False, True])
async def test_every_http_start_disables_access_even_if_caller_enables(
    monkeypatch, transport, direct
):
    from fastmcp import FastMCP

    seen = []

    async def fake_run(self, *args, **kwargs):
        seen.append(kwargs)

    monkeypatch.setattr(FastMCP, "run_http_async", fake_run)
    server = FabricMCP("bounded-test")
    start = server.run_http_async if direct else server.run_async
    caller_config = {"access_log": True, "ws": "websockets-sansio", "log_level": "warning"}
    await start(transport=transport, uvicorn_config=caller_config)
    assert seen[0]["uvicorn_config"]["log_level"] == "warning"
    assert caller_config["access_log"] is True
    assert caller_config["ws"] == "websockets-sansio"
    assert seen[0]["uvicorn_config"]["access_log"] is False
    assert seen[0]["uvicorn_config"]["ws"] == "none"
    app = server.http_app(transport=transport)
    assert isinstance(app, AccessLogMiddleware)


@pytest.mark.parametrize("transport", ["stdio", "http", "streamable-http", "sse"])
def test_cli_only_supplies_uvicorn_config_for_http(monkeypatch, transport):
    import fastmcp

    import unifi_fabric.server as srv

    class Settings:
        def get_key_configs(self):
            return [object()]

    calls = []
    config = MCPTransportSettings()
    monkeypatch.setattr(srv, "_configure_transport", lambda: config)
    monkeypatch.setattr(srv, "get_settings", Settings)
    monkeypatch.setattr(srv, "_reconcile_stateless_http", lambda: None)
    monkeypatch.setattr(srv, "_print_startup_warnings", lambda settings: None)
    monkeypatch.setattr(fastmcp.settings, "transport", transport)
    monkeypatch.setattr(srv.mcp, "run", lambda **kwargs: calls.append(kwargs))
    srv.main()
    if transport == "stdio":
        assert calls == [{}]
    else:
        assert calls == [{"uvicorn_config": {"access_log": False, "ws": "none"}}]


async def test_running_server_has_own_access_record_and_no_uvicorn_access(caplog):
    caplog.set_level(logging.INFO)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        AccessLogMiddleware(app),
        log_config=None,
        lifespan="off",
        **build_uvicorn_config(MCPTransportSettings()),
    )
    started = asyncio.Event()

    class ObservedServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            started.set()

    server = ObservedServer(config)
    task = asyncio.create_task(server.serve(sockets=[sock]))
    startup = asyncio.create_task(started.wait())
    try:
        await asyncio.wait({startup, task}, return_when=asyncio.FIRST_COMPLETED)
        if task.done():
            await task  # Surface a startup failure instead of waiting for readiness.
        assert startup.done() and server.started
        async with httpx.AsyncClient(timeout=None) as client:  # noqa: S113 -- await I/O completion
            response = await client.get(f"http://127.0.0.1:{port}/running")
        assert response.status_code == 404
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /MALFORMED_TARGET_SENTINEL\x00 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        malformed = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert malformed.startswith(b"HTTP/1.1 400")
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        target = b"/UPGRADE_TARGET_SENTINEL" + b"q" * (1025 - 24)
        # 24-byte prefix includes the slash; the target is rejected before app routing.
        assert len(target) == 1025
        writer.write(
            b"GET " + target + b" HTTP/1.1\r\nHost: localhost\r\n"
            b"Connection: upgrade\r\nUpgrade: websocket\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"  # gitleaks:allow
        )
        await writer.drain()
        response = await reader.read(4096)
        writer.close()
        await writer.wait_closed()
        assert response.startswith(b"HTTP/1.1 414")
        assert all(
            "UPGRADE_TARGET_SENTINEL" not in str(r.msg) + repr(r.args) for r in caplog.records
        )
        warnings = [
            r for r in caplog.records if r.name == "uvicorn.error" and r.levelno >= logging.WARNING
        ]
        assert warnings
        assert all(
            r.getMessage()
            in {
                "Invalid HTTP request received.",
                "Unsupported upgrade request.",
                "No supported WebSocket library detected. Please use "
                "\"pip install 'uvicorn[standard]'\", "
                "or install 'websockets' or 'wsproto' manually.",
            }
            for r in warnings
        )
        assert all(
            "MALFORMED_TARGET_SENTINEL" not in str(r.msg) + repr(r.args) for r in caplog.records
        )
        assert any(r.name == "unifi_fabric.access" for r in caplog.records)
        assert not any(r.name == "uvicorn.access" for r in caplog.records)
    finally:
        server.should_exit = True
        startup.cancel()
        await asyncio.gather(startup, return_exceptions=True)
        try:
            await task
        finally:
            sock.close()


async def test_query_values_are_masked_without_changing_request(caplog):
    caplog.set_level(logging.INFO)
    target = b"/mcp?token=QUERY_SENTINEL&empty=&token=SECOND_SENTINEL&flag"
    called, messages = await exercise(target)
    assert called[0]["query_string"] == target.partition(b"?")[2]
    assert messages[0]["status"] == 404
    assert "/mcp?***" in caplog.text
    assert "flag" not in caplog.text
    assert "token=" not in caplog.text
    assert "QUERY_SENTINEL" not in caplog.text
    assert "SECOND_SENTINEL" not in caplog.text
