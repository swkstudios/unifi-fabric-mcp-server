"""Opt-in liveness route for the HTTP transports (``MCP_HEALTH_ROUTE``).

Off by default. When ``MCP_HEALTH_ROUTE`` is on, :meth:`FabricMCP.http_app` adds
``GET /health`` to the HTTP app it builds, so stdio never serves it. The route
reports this process only and answers with one plain-text line:

* ``ok`` (HTTP 200): the event loop ran the handler, the server lifespan is running
  (settings loaded, client open), and the opt-in audit file, when configured, is
  writable by this process.
* ``degraded:<reason>`` (HTTP 503): one of those checks failed. ``<reason>`` is a
  fixed token (``config-not-loaded``, ``server-not-started`` or
  ``audit-sink-unwritable``), never a path or a value from the environment.

It never contacts a UniFi console, uses no API key, and reports no counters or
statistics. It sits inside the same Host/Origin guard and bounded access logger as
the MCP endpoint and needs no MCP token in any ``MCP_AUTH_MODE``; expose it only to
the network that runs the probe. The file-system check runs in a worker thread so a
slow mount cannot stall the event loop.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from .config import Settings

HEALTH_PATH = "/health"

#: Fixed reason tokens; a reason never carries a path or a configured value.
REASON_CONFIG = "config-not-loaded"
REASON_NOT_STARTED = "server-not-started"
REASON_AUDIT = "audit-sink-unwritable"


@dataclass(frozen=True)
class ServerState:
    """What the route may read: the lifespan-loaded settings and whether it is running."""

    settings: Settings | None
    running: bool


def _audit_sink_writable(path: str) -> bool:
    """True when this process may append to the audit file (or create it).

    Permission bits only: a full disk or quota still reads as writable.
    """
    if os.path.exists(path):
        return not os.path.isdir(path) and os.access(path, os.W_OK)
    parent = os.path.dirname(os.path.abspath(path))
    return os.path.isdir(parent) and os.access(parent, os.W_OK | os.X_OK)


def health_status(state: ServerState) -> str | None:
    """The degraded reason token, or ``None`` when healthy. Reads local state only."""
    if state.settings is None:
        return REASON_CONFIG
    if not state.running:
        return REASON_NOT_STARTED
    audit_path = (state.settings.audit_log or "").strip()
    if audit_path and not _audit_sink_writable(audit_path):
        return REASON_AUDIT
    return None


def health_route(state_provider: Callable[[], ServerState]) -> Route:
    """``GET /health`` bound to a provider of the server's lifespan state."""

    async def health(_request: Request) -> PlainTextResponse:
        reason = await asyncio.to_thread(health_status, state_provider())
        if reason is None:
            return PlainTextResponse("ok\n")
        return PlainTextResponse(f"degraded:{reason}\n", status_code=503)

    return Route(HEALTH_PATH, health, methods=["GET"], name="health")
