"""TLS reverse proxy, synthetic UniFi upstream, and MCP client for image smoke."""

import http.client
import json
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

FIXTURE = Path(tempfile.gettempdir()) / "proxy-fixture"
HOST = "fabric.example.test"
UPSTREAM_CALLS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if urlsplit(self.path).path != "/v1/hosts":
            self.send_error(404)
            return
        UPSTREAM_CALLS.append(self.path)
        body = json.dumps({"data": [{"id": "synthetic-host", "name": "Smoke Host"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        headers = {k: v for k, v in self.headers.items() if k.lower() != "connection"}
        if headers.get("Host") != HOST:
            raise AssertionError("proxy received unexpected Host")
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = HOST
        conn = http.client.HTTPConnection("127.0.0.1", 3000)
        conn.request("POST", self.path, body, headers)
        response = conn.getresponse()
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                self.send_header(key, value)
        data = response.read()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()


def start_server(port, tls=False):
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104 - isolated container network
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURE / "cert.pem", FIXTURE / "key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run(mode, scheme, expect_421, image_id, revision):
    upstream = start_server(8080)
    proxy = start_server(8443, tls=scheme == "https")
    context = ssl.create_default_context(cafile=FIXTURE / "ca.pem") if scheme == "https" else None
    session = None

    def request(method, params=None, ident=None):
        nonlocal session
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if ident is not None:
            payload["id"] = ident
        headers = {
            "Host": HOST,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer synthetic-proxy-smoke-token",
        }
        if session:
            headers["Mcp-Session-Id"] = session
        conn = (
            http.client.HTTPSConnection("localhost", 8443, context=context)
            if context
            else http.client.HTTPConnection("localhost", 8443)
        )
        conn.request("POST", "/mcp", json.dumps(payload), headers)
        response = conn.getresponse()
        body = response.read().decode()
        if expect_421 and method == "initialize":
            assert response.status == 421, f"{mode}: expected 421, got {response.status}"
            print(f"{mode} initialize: expected HTTP 421", flush=True)
            return None
        if response.status not in (200, 202):
            raise AssertionError(f"{mode} {method}: HTTP {response.status}: {body[:500]}")
        session = response.getheader("Mcp-Session-Id", session)
        conn.close()
        if ident is None:
            return None
        lines = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
        message = json.loads(lines[0] if lines else body)
        if message.get("id") != ident or "result" not in message:
            raise AssertionError(f"{mode} {method}: invalid response {message}")
        print(f"{mode} {method}: HTTP {response.status}", flush=True)
        return message["result"]

    result = request(
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "proxy-smoke", "version": "1"},
        },
        1,
    )
    if expect_421:
        print(
            json.dumps(
                {
                    "kind": "proxy-smoke",
                    "mode": mode,
                    "scheme": scheme,
                    "host": HOST,
                    "image_id": image_id,
                    "revision": revision,
                    "outcome": "expected-421",
                    "initialize_http": 421,
                }
            ),
            flush=True,
        )
        proxy.shutdown()
        upstream.shutdown()
        return
    assert result["protocolVersion"]
    assert bool(session) == (mode == "stateful"), f"{mode}: unexpected session header"
    request("notifications/initialized")
    result = request("tools/list", {}, 2)
    assert "call_read_tool" in {tool["name"] for tool in result["tools"]}
    result = request(
        "tools/call",
        {"name": "call_read_tool", "arguments": {"name": "list_hosts", "arguments": {}}},
        3,
    )
    assert not result.get("isError"), result
    assert "synthetic-host" in json.dumps(result), result
    assert len(UPSTREAM_CALLS) == 1, UPSTREAM_CALLS
    print(f"{mode}: verified synthetic upstream {UPSTREAM_CALLS[0]}", flush=True)
    print(
        json.dumps(
            {
                "kind": "proxy-smoke",
                "mode": mode,
                "scheme": scheme,
                "host": HOST,
                "image_id": image_id,
                "revision": revision,
                "outcome": "PASS",
                "initialize": True,
                "tools_list": True,
                "tools_call": True,
                "upstream_path": UPSTREAM_CALLS[0],
                "upstream_calls": len(UPSTREAM_CALLS),
            }
        ),
        flush=True,
    )
    proxy.shutdown()
    upstream.shutdown()


if __name__ == "__main__":
    import sys

    run(sys.argv[1], sys.argv[2], sys.argv[3] == "expect-421", sys.argv[4], sys.argv[5])
