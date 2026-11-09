"""Bound HTTP request heads before auth and emit server-owned access records."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

B_TARGET = 1024
B_HEADERS = 16 * 1024
_logger = logging.getLogger("unifi_fabric.access")
_BODIES = {414: b"Request target too large\n", 431: b"Request headers too large\n"}
#: Log form of each request-target byte: printable ASCII as is; control bytes (ESC, CR,
#: LF) and non-ASCII as ``\\xNN``, the form ``backslashreplace`` already gave non-ASCII
#: and the log scrubber matches. The line is built from this fixed table, never from the
#: raw request bytes, so no terminal escape or line break reaches the access record
#: (CodeQL py/clear-text-logging-sensitive-data).
_BYTE_TEXT = tuple(chr(b) if 0x20 <= b < 0x7F else f"\\x{b:02x}" for b in range(256))


def _printable(raw: bytes) -> str:
    """The request target as one printable ASCII token for the access line."""
    return "".join(_BYTE_TEXT[b] for b in raw)


class AccessLogMiddleware:
    """Outermost ASGI boundary; reject oversized heads without entering the app.

    Header field bytes include ``name: value\r\n`` and the terminating CRLF.
    Rejected requests log only the target's size and digest, never header values.
    The existing record factory and filters scrub these records like every other log.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def __getattr__(self, name: str) -> Any:
        # FastMCP and ASGI test clients also use the wrapped Starlette state/router.
        return getattr(self.app, name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw_path = scope.get("raw_path", scope.get("path", "").encode("utf-8"))
        query = scope.get("query_string", b"")
        target = raw_path + (b"?" + query if query else b"")
        header_bytes = 2 + sum(len(name) + len(value) + 4 for name, value in scope["headers"])
        rejection = 414 if len(target) > B_TARGET else 431 if header_bytes > B_HEADERS else None
        if rejection is not None:
            logged_target = (
                f"<target withheld: {len(target)} bytes "
                f"sha256:{hashlib.sha256(target).hexdigest()[:16]}>"
            )
        else:
            # Query keys and bare tokens can themselves be credentials.
            safe_query = b"***"
            logged_target = _printable(raw_path + (b"?" + safe_query if query else b""))
        status = 500
        logged = False

        def log_access() -> None:
            nonlocal logged
            if not logged:
                logged = True
                client = scope.get("client")
                client_text = f"{client[0]}:{client[1]}" if client else "-"
                _logger.info(
                    '%s - "%s %s HTTP/%s" %s',
                    client_text,
                    scope["method"],
                    logged_target,
                    scope.get("http_version", "1.1"),
                    status,
                )

        async def send_logged(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                log_access()
            await send(message)

        try:
            if rejection is not None:
                body = _BODIES[rejection]
                await send_logged(
                    {
                        "type": "http.response.start",
                        "status": rejection,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    }
                )
                await send_logged({"type": "http.response.body", "body": body})
            else:
                await self.app(scope, receive, send_logged)
        finally:
            log_access()
