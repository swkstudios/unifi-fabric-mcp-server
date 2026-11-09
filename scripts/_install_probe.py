"""Synthetic Site Manager upstream shared by the install-path probes.

``scripts/install_smoke.py`` and ``scripts/install_matrix.py`` both start the installed
server against a local stand-in for the Site Manager API: a request carrying the accepted
key lists one synthetic host, any other key gets the upstream 401 body. The two callers
differ only in two parameters, which each passes explicitly:

``bind``          the listening address. The install smoke binds every interface so a
                  Docker container can reach the mock through the host gateway; the
                  install matrix binds the loopback address only.
``accepted_key``  the key policy: the one ``X-API-KEY`` value the mock accepts (each caller
                  has its own synthetic key, so a key from one probe never passes the other).

The returned base URL always names the loopback address; a container rewrites the host
part itself.
"""

from __future__ import annotations

import http.server
import json
import threading

LOOPBACK = "127.0.0.1"
ALL_INTERFACES = "0.0.0.0"  # noqa: S104 - only for a Docker-reachable synthetic mock


def mock_handler(accepted_key: str) -> type[http.server.BaseHTTPRequestHandler]:
    """A request handler that accepts ``accepted_key`` and answers 401 to anything else."""
    if not accepted_key:
        raise ValueError("the mock needs a non-empty accepted key")

    class _MockAPI(http.server.BaseHTTPRequestHandler):
        """Site Manager stand-in: a valid key lists one synthetic host, anything else is 401."""

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if self.headers.get("X-API-KEY") != accepted_key:
                body = {"code": "unauthorized", "message": "Unauthorized", "statusCode": 401}
                self._send(401, body)
            elif self.path.split("?", 1)[0] == "/v1/hosts":
                hosts = [{"id": "0" * 32, "type": "console"}]
                self._send(200, {"data": hosts, "httpStatusCode": 200})
            else:
                self._send(200, {"data": [], "httpStatusCode": 200})

        def _send(self, status: int, body: dict) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args: object) -> None:
            return

    return _MockAPI


def start_mock(
    accepted_key: str, *, bind: str = LOOPBACK
) -> tuple[http.server.ThreadingHTTPServer, str]:
    """Serve the mock on ``bind`` at a free port; return the server and its loopback URL."""
    if bind not in (LOOPBACK, ALL_INTERFACES):
        raise ValueError(f"bind address {bind!r} is neither {LOOPBACK} nor {ALL_INTERFACES}")
    server = http.server.ThreadingHTTPServer((bind, 0), mock_handler(accepted_key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{LOOPBACK}:{server.server_address[1]}"
