"""Wire-level payload survival across MCP revisions, with no estate credentials.

Sources: https://modelcontextprotocol.io/specification/2026-07-28/changelog
and each revision's basic/lifecycle and server/tools specifications. Older peers
receive the complete JSON text fallback when structuredContent is not in their
wire schema. Duplicate serialization is deliberately preserved.
"""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import subprocess
import sys
import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport
from mcp.client import stdio as mcp_stdio
from mcp.shared.jsonrpc_dispatcher import JSONRPCDispatcher

VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28")
MODERN = VERSIONS[-1]
_MATCH_META = object()
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
INFO_KEY = "io.modelcontextprotocol/clientInfo"
SYNTHETIC_KEY = "synthetic-protocol-conformance-only"
IMAGE = bytes(range(256)) * 48
CONTENT_TYPE = "image/png; profile=synthetic"
REASON = "upstream-full-reason:" + "failure detail Ω " * 1500 + ":end-of-reason"
HOST = {
    "id": "001122334455:123456789",
    "reportedState": {"hostname": "mock-console", "apps": [{"name": "protect"}]},
    "unknown": {"null": None, "empty": [], "bool": False, "unicode": "東京 Ω"},
    "long": "all-fields-survive:" + "payload " * 2000 + ":end-of-payload",
}
PAYLOAD = {"data": [HOST], "httpStatusCode": 200, "traceId": "synthetic-trace", "extra": {"n": 0}}
ROOT = Path(__file__).resolve().parents[1]

# These cases start the complete catalog in child processes. Keep their server
# lifetimes together while the rest of the suite still uses all four workers.
pytestmark = pytest.mark.xdist_group("protocol-conformance")


@pytest.fixture
def upstream():
    """A real loopback HTTP upstream verifies the synthetic key on every read."""
    calls = []
    failures = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            calls.append((self.path, self.headers.get("X-API-KEY")))
            assert self.headers.get("X-API-KEY") == SYNTHETIC_KEY
            if failures.is_set():
                status, body, mime = (
                    403,
                    json.dumps({"message": REASON}, ensure_ascii=False).encode(),
                    "application/json",
                )
            elif self.path.split("?")[0] == "/v1/hosts":
                status, body, mime = 200, json.dumps(PAYLOAD).encode(), "application/json"
            elif self.path.split("?")[0].endswith("/cameras/mock-camera/snapshot"):
                status, body, mime = 200, IMAGE, CONTENT_TYPE
            else:
                status, body, mime = 404, b'{"message":"unexpected mock route"}', "application/json"
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls, failures
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def server_env(upstream_url, transport, port=0):
    # Explicit environment: no inherited credentials, proxy or optional product flags.
    return {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "src"),
        "UNIFI_API_KEY": SYNTHETIC_KEY,
        "UNIFI_API_BASE_URL": upstream_url,
        "UNIFI_LOG_LEVEL": "ERROR",
        "FASTMCP_TRANSPORT": transport,
        "FASTMCP_HOST": "127.0.0.1",
        "FASTMCP_PORT": str(port),
        "MCP_AUTH_MODE": "none",
    }


class Wire:
    def __init__(self, process, url=None):
        self.process = process
        self.url = url
        self.client = (
            httpx.AsyncClient(timeout=None, trust_env=False) if url else None  # noqa: S113 -- await local server response
        )
        self.session = None
        self.version = MODERN
        self.counter = 0

    async def send(
        self,
        method,
        params=None,
        *,
        version=MODERN,
        envelope=True,
        notify=False,
        http_version=_MATCH_META,
    ):
        self.counter += 1
        body = {"jsonrpc": "2.0", "method": method, "params": dict(params or {})}
        if not notify:
            body["id"] = self.counter
        if envelope:
            meta = {CAPABILITIES_KEY: {}, INFO_KEY: {"name": "claude-code", "version": "synthetic"}}
            if version is not None:
                meta[VERSION_KEY] = version
            body["params"]["_meta"] = meta
        if self.url:
            assert self.client is not None
            headers = {"Accept": "application/json, text/event-stream", "Mcp-Method": method}
            header_version = version if http_version is _MATCH_META else http_version
            if header_version is not None:
                headers["MCP-Protocol-Version"] = header_version
            if method == "tools/call":
                headers["Mcp-Name"] = body["params"]["name"]
            if self.session and not envelope:
                headers["Mcp-Session-Id"] = self.session
            response = await self.client.post(self.url, json=body, headers=headers)
            assert response.request.extensions["timeout"] == {
                "connect": None,
                "read": None,
                "write": None,
                "pool": None,
            }
            assert response.status_code in (200, 202, 400), (response.status_code, response.text)
            if "Mcp-Session-Id" in response.headers:
                # SDK streamable_http_manager routes every non-handshake header
                # to the single-exchange modern handler, including invalid bodies.
                assert header_version in (*VERSIONS[:-1], None), (
                    "modern HTTP requests must not create protocol sessions"
                )
                self.session = response.headers["Mcp-Session-Id"]
            if notify:
                return None
            if "text/event-stream" in response.headers.get("Content-Type", ""):
                frames = [
                    json.loads(line[6:])
                    for line in response.text.splitlines()
                    if line.startswith("data: ")
                ]
                return next(frame for frame in frames if frame.get("id") == body["id"])
            return response.json()
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(json.dumps(body) + "\n")
        self.process.stdin.flush()
        if notify:
            return None

        def read_response():
            while line := self.process.stdout.readline():
                frame = json.loads(line)
                if frame.get("id") == body["id"]:
                    return frame
            raise AssertionError(f"server exited with {self.process.poll()}")

        return await asyncio.to_thread(read_response)

    async def negotiate(self, version):
        self.version = version
        if version == MODERN:
            response = await self.send("server/discover")
            result = response["result"]
            assert MODERN in result["supportedVersions"]
            assert result["resultType"] == "complete"
            assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "UniFi Fabric"
        else:
            response = await self.send(
                "initialize",
                {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "protocol-matrix", "version": "1"},
                },
                version=None,
                envelope=False,
            )
            assert response["result"]["protocolVersion"] == version
            await self.send(
                "notifications/initialized", version=version, envelope=False, notify=True
            )

    async def tool(self, name, arguments=None):
        response = await self.send(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            version=self.version,
            envelope=self.version == MODERN,
        )
        assert "result" in response, response
        result = response["result"]
        if self.version == MODERN:
            assert result["resultType"] == "complete"
        return result


# The HTTP server serves on a socket the test bound and is already listening on: the
# child inherits it (``pass_fds``) and Uvicorn serves on it through its ``fd`` setting, so
# the port is never free for another process to take between selection and serving. It
# prints a marker once Uvicorn has completed startup.
_HTTP_READY = "TEST_HTTP_READY"
_HTTP_SERVER = """
import uvicorn
original_init = uvicorn.Config.__init__
def init(self, *args, **kwargs):
    original_init(self, *args, **{{**kwargs, "fd": {fd}}})
uvicorn.Config.__init__ = init
original_startup = uvicorn.Server.startup
async def startup(self, *args, **kwargs):
    await original_startup(self, *args, **kwargs)
    if self.started:
        print("{ready}", flush=True)
uvicorn.Server.startup = startup
from unifi_fabric.server import main
main()
"""


@pytest.fixture(params=("stdio", "streamable-http"))
async def wire(request, upstream, tmp_path):
    transport = request.param
    port = 0
    code = "from unifi_fabric.server import main; main()"
    listener = None
    pass_fds: tuple[int, ...] = ()
    if transport != "stdio":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        code = _HTTP_SERVER.format(fd=listener.fileno(), ready=_HTTP_READY)
        pass_fds = (listener.fileno(),)
    stderr = (tmp_path / "server.stderr").open("w+")
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test-owned code
            [sys.executable, "-u", "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            env=server_env(upstream[0], transport, port),
            cwd=tmp_path,
            pass_fds=pass_fds,
        )
    finally:
        # The child holds its own copy of the listening socket from the fork onward, so
        # the parent's copy is closed once the child exists; the port stays bound.
        if listener is not None:
            listener.close()
    instance = Wire(process, f"http://127.0.0.1:{port}/mcp" if port else None)
    try:
        if port:
            # Read output until the readiness marker; end of output means the server
            # exited before completing startup.
            while (line := await asyncio.to_thread(process.stdout.readline)) != "":
                if line.strip() == _HTTP_READY:
                    break
            else:
                await asyncio.to_thread(process.wait)
                stderr.seek(0)
                pytest.fail(stderr.read(2000))
        yield instance
    finally:
        if instance.client is not None:
            await instance.client.aclose()
        if process.poll() is None:
            process.terminate()
            await asyncio.to_thread(process.wait)
        for stream in (process.stdin, process.stdout, stderr):
            if stream:
                stream.close()


def json_content(result, version):
    texts = [block["text"] for block in result["content"] if block["type"] == "text"]
    assert len(texts) == 1, result
    payload = json.loads(texts[0])
    if version >= "2025-06-18":
        assert result["structuredContent"] == payload
    elif "structuredContent" in result:
        assert result["structuredContent"] == payload
    return payload


@pytest.mark.parametrize("version", VERSIONS)
async def test_full_payload_binary_and_error_matrix(wire, upstream, version):
    await wire.negotiate(version)
    listed = await wire.tool("list_hosts")
    assert not listed.get("isError", False)
    assert json_content(listed, version) == {**PAYLOAD, "_count": 1}
    binary = await wire.tool(
        "get_camera_snapshot", {"host": "mock-console", "camera_id": "mock-camera"}
    )
    assert not binary.get("isError", False)
    metadata = json_content(binary, version)
    assert metadata == {
        "image_base64": base64.b64encode(IMAGE).decode(),
        "content_type": CONTENT_TYPE,
        "size_bytes": len(IMAGE),
    }
    (image,) = [block for block in binary["content"] if block["type"] == "image"]
    assert base64.b64decode(image["data"], validate=True) == IMAGE
    assert image["mimeType"] == "image/png"
    upstream[2].set()
    error = await wire.tool("list_hosts")
    assert error["isError"] is True
    error_text = "\n".join(block.get("text", "") for block in error["content"])
    assert json.dumps({"message": REASON}, ensure_ascii=False) in error_text
    assert REASON in error_text
    assert len(upstream[1]) == 3
    assert all(key == SYNTHETIC_KEY for _, key in upstream[1])


@pytest.mark.parametrize("version", ("", "malformed", "2026-99-99", "2099-01-01"))
async def test_malformed_version_is_minus_32022_and_connection_survives(wire, upstream, version):
    response = await wire.send(
        "tools/call", {"name": "list_hosts", "arguments": {}}, version=version
    )
    assert response["error"]["code"] == -32022
    assert response["error"]["data"] == {"supported": [MODERN], "requested": version}
    assert not upstream[1], "invalid version must not reach the upstream"
    await wire.negotiate(MODERN)
    assert json_content(await wire.tool("list_hosts"), MODERN) == {**PAYLOAD, "_count": 1}


async def test_missing_request_version_is_rejected_and_connection_survives(wire, upstream):
    # Start modern first: stdio selects its protocol era on the opening request.
    await wire.negotiate(MODERN)
    response = await wire.send(
        "tools/call", {"name": "list_hosts", "arguments": {}}, version=None, http_version=MODERN
    )
    # This is the installed SDK's classifier behavior, not a product-specific
    # error policy: mcp/shared/inbound.py classify_inbound_request rung 1 rejects
    # missing envelope keys as INVALID_PARAMS. The HTTP header stays modern.
    assert response["error"]["code"] == -32602
    assert VERSION_KEY in response["error"]["message"]
    assert not upstream[1]
    assert json_content(await wire.tool("list_hosts"), MODERN) == {**PAYLOAD, "_count": 1}


async def test_missing_legacy_initialize_version_is_invalid_params(wire, upstream):
    response = await wire.send(
        "initialize",
        {"capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        version=None,
        envelope=False,
    )
    assert response["error"]["code"] == -32602
    assert not upstream[1]
    await wire.negotiate("2025-03-26")
    assert json_content(await wire.tool("list_hosts"), "2025-03-26") == {**PAYLOAD, "_count": 1}


async def test_claude_code_style_default_negotiation_read(wire, upstream, tmp_path, monkeypatch):
    """Default auto probe, no forced version; Claude Code's modern request shape.

    FastMCP is the deterministic client here, not an authenticated Claude model
    invocation. Raw-wire tests above additionally enforce the per-request envelope.
    """
    sent = []
    original = JSONRPCDispatcher.send_raw_request

    async def capture(dispatcher, method, params=None, opts=None, **kwargs):
        # Observe fully stamped outbound messages at the transport boundary;
        # no version override is supplied to Client below.
        sent.append((method, json.loads(json.dumps(params))))
        return await original(dispatcher, method, params, opts, **kwargs)

    monkeypatch.setattr(JSONRPCDispatcher, "send_raw_request", capture)
    if wire.url:
        transport = wire.url
    else:
        runner = tmp_path / "client-server.py"
        ready = tmp_path / "client-server.serving"
        stderr_log = tmp_path / "client-server.stderr"
        # The runner always writes the marker, atomically (temp file, then rename). "ok"
        # means serving-ready: the server lifespan has run, the stdio streams are open,
        # and the low-level server is starting the loop that reads stdin, so the first
        # request is answered without the startup work in front of it. Anything else is
        # the repr of the exception that stopped the import, the server build or main()
        # before then, or the status of a runner that stopped without serving.
        runner.write_text(
            "import os\n"
            "from pathlib import Path\n"
            f"ready = Path({str(ready)!r})\n"
            "def mark(status):\n"
            "    partial = ready.with_name(ready.name + '.partial')\n"
            "    partial.write_text(status)\n"
            "    os.replace(partial, ready)\n"
            "try:\n"
            "    from unifi_fabric import server\n"
            "    if server.mcp is None:\n"
            "        raise RuntimeError('the server module built no server object')\n"
            "    lowlevel = server.mcp._mcp_server\n"
            "    serve = lowlevel.run\n"
            "    async def run_when_serving(*args, **kwargs):\n"
            "        mark('ok')\n"
            "        return await serve(*args, **kwargs)\n"
            "    lowlevel.run = run_when_serving\n"
            "    server.main()\n"
            "except BaseException as exc:\n"
            "    if not ready.exists():\n"
            "        mark(repr(exc))\n"
            "    raise\n"
            "finally:\n"
            "    if not ready.exists():\n"
            "        mark('runner stopped before the server started serving')\n"
        )
        spawned = []
        spawn = mcp_stdio._create_platform_compatible_process

        async def record_spawn(*args, **kwargs):
            process = await spawn(*args, **kwargs)
            spawned.append(process)
            return process

        monkeypatch.setattr(mcp_stdio, "_create_platform_compatible_process", record_spawn)

        class ServingReadyTransport(PythonStdioTransport):
            @asynccontextmanager
            async def connect_session(self, **kwargs):
                async with super().connect_session(**kwargs) as session:
                    # Wait for the serving-ready marker before yielding the session, so
                    # the first unmodified auto probe reaches a server that is already
                    # reading stdin: the SDK bounds that probe (DISCOVER_TIMEOUT_SECONDS)
                    # and falls back to initialize when startup work outlasts it.
                    # A runner that exits without writing the marker ends the wait too.
                    while not ready.exists():
                        if spawned and spawned[-1].returncode is not None:
                            pytest.fail(
                                "server runner exited with code "
                                f"{spawned[-1].returncode} before writing its serving "
                                f"marker; stderr:\n{stderr_log.read_text()}"
                            )
                        await asyncio.sleep(0.05)
                    assert ready.read_text() == "ok", ready.read_text()
                    yield session

        transport = ServingReadyTransport(
            script_path=runner,
            python_cmd=sys.executable,
            env=server_env(upstream[0], "stdio"),
            cwd=tmp_path,
            keep_alive=False,
            log_file=stderr_log,
        )
    async with Client(transport, name="claude-code") as client:
        assert client.protocol_version == MODERN
        assert client.initialize_result is None
        result = await client.call_tool("list_hosts")
        assert result.structured_content == {**PAYLOAD, "_count": 1}
        assert json.loads(result.content[0].text) == result.structured_content
    assert sent[0][0] == "server/discover"
    assert "initialize" not in [method for method, _ in sent]
    assert "tools/call" in [method for method, _ in sent]
    for method, params in sent:
        assert params["_meta"][VERSION_KEY] == MODERN, method
        assert CAPABILITIES_KEY in params["_meta"], method
    assert upstream[1]
    assert all(key == SYNTHETIC_KEY for _, key in upstream[1])


@pytest.mark.parametrize("version", ("malformed", "2099-01-01"))
async def test_legacy_unknown_version_counteroffers_latest_handshake(wire, upstream, version):
    # Legacy initialize negotiates unknown string offers via a counteroffer;
    # modern per-request version failures instead use -32022 (tested above).
    response = await wire.send(
        "initialize",
        {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "legacy-negotiation", "version": "1"},
        },
        version=None,
        envelope=False,
    )
    assert response["result"]["protocolVersion"] == "2025-11-25"
    wire.version = "2025-11-25"
    await wire.send("notifications/initialized", version=wire.version, envelope=False, notify=True)
    assert json_content(await wire.tool("list_hosts"), wire.version) == {**PAYLOAD, "_count": 1}
    assert len(upstream[1]) == 1


async def test_missing_legacy_http_version_header_keeps_payload(wire, upstream):
    await wire.negotiate("2025-03-26")
    response = await wire.send(
        "tools/call", {"name": "list_hosts", "arguments": {}}, version=None, envelope=False
    )
    assert json_content(response["result"], "2025-03-26") == {**PAYLOAD, "_count": 1}
    assert len(upstream[1]) == 1


@pytest.mark.parametrize("wire", ("streamable-http",), indirect=True)
@pytest.mark.parametrize("header_version", (None, "2025-11-25"))
async def test_modern_envelope_on_legacy_http_route_is_rejected(wire, upstream, header_version):
    assert wire.url
    response = await wire.send(
        "tools/call", {"name": "list_hosts", "arguments": {}}, http_version=header_version
    )
    # Missing HTTP version defaults to the legacy era; an explicit legacy
    # version also selects it (MCP SDK streamable_http_manager.py). A modern
    # envelope on that route is INVALID_REQUEST, not a modern header mismatch.
    # Modern-header missing-body-version validation is tested separately above.
    assert response["error"]["code"] == -32600
    assert not upstream[1]
    await wire.negotiate(MODERN)
    assert json_content(await wire.tool("list_hosts"), MODERN) == {**PAYLOAD, "_count": 1}
