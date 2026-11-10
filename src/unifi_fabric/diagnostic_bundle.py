"""A sanitized, reviewable diagnostic bundle describing this MCP server.

The bundle answers "what is this server, how is it configured and is it reaching the
Site Manager API?" without the operator assembling it by hand. It is built for sharing
in a bug report, so it is built from an allowlist: each field below is named here and
is an enum, a boolean, a number, a count, a version string or a fixed token. Nothing is
read from the environment except the documented settings models, no file is read, no
command is run, and no free-form value (paths, URLs, hosts, ports, key labels, upstream
bodies or exception messages) is copied.

Collection:

* Default (no ``live_probes``): local and cached state only. The bundle sends no
  request to any UniFi console or to the Site Manager API; ``collection.upstreamRequests``
  is the count the client chokepoint recorded during the call, so the claim is checked,
  not asserted.
* ``live_probes``: a closed allowlist (:data:`LIVE_PROBES`) of existing read-only list
  tools, run once per configured key through the same read helpers those tools use. A
  probe result is a summary per key (status, record count, duration and a bounded
  reason from :func:`unifi_fabric.client.log_reason`); no upstream record is copied.

Every section carries a ``status`` (:data:`SECTION_STATUSES`) and a ``source`` naming
where its data came from. One section failing never fails the bundle: it is reported
``failed`` with an exception type name only, never its message.

Last, the whole result passes the central scrubber for the server's configured secrets
(:func:`unifi_fabric.secret_scrub.scrub_json_strings`), and the serialized result is
checked with :func:`unifi_fabric.secret_scrub.contains_secret`; the outcome is reported
under ``sanitization``.

The bundle is returned in the tool response only. The server writes it nowhere and
sends it nowhere: the user reviews it and decides whether to share it.

Design credit: the separation of cached diagnostics from explicitly allowlisted live
probes follows the sanitized support-bundle design of sirkirby/unifi-mcp (MIT,
Copyright (c) 2025 Chris Kirby), pinned at commit
7a40f40fd2af69bc5cd0c6b531888f54601cc613. No code was copied from it.
"""

from __future__ import annotations

import json
import platform
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Literal

from . import audit, policy
from .client import log_reason
from .contracts import policy_digest
from .secret_scrub import configured_secrets, contains_secret, scrub_json_strings

if TYPE_CHECKING:
    from .client import UniFiClient
    from .registry import Registry

#: Version of the bundle layout; bumped when a field is renamed or removed.
SCHEMA_VERSION: Final = 1
PACKAGE: Final = "unifi-fabric-mcp-server"

#: Section outcomes: every section has exactly one.
COMPLETE: Final = "complete"
PARTIAL: Final = "partial"
FAILED: Final = "failed"
UNAVAILABLE: Final = "unavailable"
SECTION_STATUSES: Final = (COMPLETE, PARTIAL, FAILED, UNAVAILABLE)

LiveProbe = Literal["hosts", "sites"]

#: The documented live-probe allowlist: probe name -> (existing read tool, route).
LIVE_PROBES: Final[dict[str, tuple[str, str]]] = {
    "hosts": ("list_hosts", "GET /v1/hosts"),
    "sites": ("list_sites", "GET /v1/sites"),
}

#: Runtime dependencies whose installed version is reported (names only, fixed list).
DEPENDENCIES: Final = ("fastmcp", "mcp", "httpx", "pydantic", "pydantic-settings", "cachetools")

#: What the bundle never collects, stated in every bundle so a reviewer can check it.
NEVER_COLLECTED: Final = (
    "API key values and key labels (keys are numbered)",
    "bearer tokens, TLS key passwords, OAuth settings other than the auth mode",
    "file paths, host names, IP addresses, ports, URLs and the API base URL",
    "environment variables other than the documented settings summarized here",
    "upstream response bodies, headers and error messages",
    "console, site, device and client identifiers or names",
)

_OS_FAMILIES: Final = {"linux": "linux", "darwin": "macos", "win32": "windows"}
_ARCHITECTURES: Final = frozenset({"x86_64", "amd64", "arm64", "aarch64"})
_TRANSPORTS: Final = frozenset({"stdio", "http", "streamable-http", "sse"})
_LOG_LEVELS: Final = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

ProbeFetch = Callable[[str], Awaitable[Any]]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _section(source: str, build: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run one section builder; a failure is that section's ``failed`` status only.

    The exception's message is never kept: it may hold the input it rejected.
    """
    try:
        data = build()
    except Exception as exc:
        return {"status": FAILED, "source": source, "reason": type(exc).__name__}
    status = data.pop("_status", COMPLETE)
    return {"status": status, "source": source, "data": data}


def _installed(name: str) -> str | None:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _server() -> dict[str, Any]:
    deps = {name: _installed(name) for name in DEPENDENCIES}
    machine = platform.machine().lower()
    data: dict[str, Any] = {
        "package": PACKAGE,
        "version": _installed(PACKAGE),
        "python": platform.python_version(),
        "pythonImplementation": platform.python_implementation(),
        "os": _OS_FAMILIES.get(sys.platform, "other"),
        "architecture": machine if machine in _ARCHITECTURES else "other",
        "dependencies": deps,
    }
    if data["version"] is None or None in deps.values():
        data["_status"] = PARTIAL
    return data


def _choice(value: Any, allowed: frozenset[str] | tuple[str, ...]) -> str | None:
    """``value`` when it is one of ``allowed``; otherwise the fixed token ``other``."""
    if value is None:
        return None
    return value if value in allowed else "other"


#: Credential-provider settings (key file / helper command). Only whether each is set is
#: reported: never a path, an argument or a name. Read with ``getattr`` so the summary is
#: the same whether or not this build defines the setting (an absent one is unset).
_PROVIDER_SETTINGS = {
    "keyFile": "api_key_file",
    "keysFile": "api_keys_file",
    "keyCommand": "api_key_command",
    "keysCommand": "api_keys_command",
}


def _provider_flags(settings: Any) -> dict[str, bool]:
    flags: dict[str, bool] = {}
    for name, attr in _PROVIDER_SETTINGS.items():
        value = getattr(settings, attr, None)
        flags[name] = bool(value.strip()) if isinstance(value, str) else bool(value)
    return flags


def _configuration(client: UniFiClient) -> dict[str, Any]:
    from .header_credentials import key_mode

    settings = client._settings  # noqa: SLF001 - the client's loaded Settings
    keys = settings.get_key_configs()
    data: dict[str, Any] = {
        "toolMode": settings.tool_mode,
        "apiKeys": {
            "count": len(keys),
            "organizationKeys": sum(k.is_org_key for k in keys),
            "providers": _provider_flags(settings),
        },
        "customApiBaseUrl": settings.api_base_url.rstrip("/") != "https://api.ui.com",
        "redactSecrets": settings.redact_secrets,
        "cacheTtlSeconds": settings.cache_ttl_seconds,
        "cacheMaxHosts": settings.cache_max_hosts,
        "cacheMaxSites": settings.cache_max_sites,
        "maxConcurrency": settings.max_concurrency,
        "paginateMaxPages": settings.paginate_max_pages,
        "logLevel": _choice(settings.log_level.upper(), _LOG_LEVELS),
        "audit": {
            "logFileConfigured": bool(settings.audit_log.strip()),
            "format": _choice(settings.audit_log_format.lower(), ("json", "text")),
            "sink": _choice(settings.audit_sink.lower() or None, audit.SINKS),
            "level": _choice(settings.audit_level.lower(), ("off", "normal", "debug")),
            "calls": settings.audit_calls,
        },
    }
    try:
        data["keyMode"] = key_mode()
    except Exception as exc:
        data["keyMode"] = None
        data["keyModeError"] = type(exc).__name__
        data["_status"] = PARTIAL
    return data


def _policy() -> dict[str, Any]:
    effective = policy.current()
    return {
        "effectivePolicy": policy.canonical_policy_object(effective),
        "digest": policy_digest(effective),
    }


def _transport() -> dict[str, Any]:
    import fastmcp

    from .config import MCPTransportSettings

    transport = MCPTransportSettings()
    return {
        "transport": _choice(fastmcp.settings.transport, _TRANSPORTS),
        "authMode": transport.auth_mode,
        "tlsMode": transport.tls_mode,
        "healthRoute": transport.health_route,
        "hostOriginProtection": transport.host_origin_protection,
        "allowedHostsCount": len(transport.allowed_hosts),
        "allowedOriginsCount": len(transport.allowed_origins),
        "oauthWriteScopeConfigured": bool(transport.oauth_write_scope.strip()),
    }


def _cache(registry: Registry) -> dict[str, Any]:
    counts = registry.cache_counts()
    return dict(counts)


async def _probe(name: str, labels: list[str], fetch: ProbeFetch) -> dict[str, Any]:
    tool, route = LIVE_PROBES[name]
    results: list[dict[str, Any]] = []
    for number, label in enumerate(labels, start=1):
        started = time.monotonic()
        entry: dict[str, Any] = {"key": number}
        try:
            body = await fetch(label)
        except Exception as exc:
            entry.update(status=FAILED, reason=log_reason(exc))
        else:
            data = body.get("data") if isinstance(body, dict) else None
            if not isinstance(data, list):
                entry.update(status=FAILED, reason="unexpected-shape")
            elif body.get("incomplete"):
                entry.update(status=PARTIAL, records=len(data), reason="incomplete")
            else:
                entry.update(status=COMPLETE, records=len(data))
        entry["durationMs"] = round((time.monotonic() - started) * 1000)
        results.append(entry)
    statuses = {r["status"] for r in results}
    if not results:
        status = UNAVAILABLE
    elif statuses == {COMPLETE}:
        status = COMPLETE
    elif statuses == {FAILED}:
        status = FAILED
    else:
        status = PARTIAL
    return {"probe": name, "tool": tool, "route": route, "status": status, "keys": results}


def validate_probes(live_probes: Sequence[str] | None) -> list[str]:
    """The requested probes in allowlist order; an unknown name fails before any work."""
    if not live_probes:
        return []
    unknown = sorted({p for p in live_probes if p not in LIVE_PROBES}, key=str)
    if unknown:
        raise ValueError(
            f"live_probes: unknown probe(s) {unknown}; valid probes: {sorted(LIVE_PROBES)}"
        )
    return [name for name in LIVE_PROBES if name in live_probes]


async def _live(
    client: UniFiClient, probes: list[str], fetchers: dict[str, ProbeFetch]
) -> dict[str, Any]:
    if not probes:
        return {
            "status": UNAVAILABLE,
            "source": "live:not-requested",
            "reason": "no live probe requested; pass live_probes to run one",
        }
    try:
        labels = client.list_key_labels()
    except Exception as exc:
        return {"status": FAILED, "source": "live:site-manager", "reason": type(exc).__name__}
    if not labels:
        return {"status": UNAVAILABLE, "source": "live:site-manager", "reason": "no-api-key"}
    results = [await _probe(name, labels, fetchers[name]) for name in probes]
    statuses = {r["status"] for r in results}
    status = COMPLETE if statuses == {COMPLETE} else FAILED if statuses == {FAILED} else PARTIAL
    return {"status": status, "source": "live:site-manager", "probes": results}


async def build_bundle(
    client: UniFiClient,
    registry: Registry,
    *,
    live_probes: list[str] | None,
    fetchers: dict[str, ProbeFetch],
    tool_count: Callable[[], Awaitable[int]],
) -> dict[str, Any]:
    """Assemble, scrub and return the bundle (see the module docstring).

    ``fetchers`` maps each allowlisted probe to the existing read helper it runs for one
    key label; ``tool_count`` counts the registered tools (local state).
    """
    probes = validate_probes(live_probes)
    with policy.upstream_call_scope() as counter:
        sections: dict[str, Any] = {
            "server": _section("local:package-metadata", _server),
            "configuration": _section("local:settings", lambda: _configuration(client)),
            "policy": _section("local:operator-policy", _policy),
            "transport": _section("local:transport-settings", _transport),
            "cache": _section("cache:registry", lambda: _cache(registry)),
        }
        try:
            count = await tool_count()
        except Exception as exc:
            sections["runtime"] = {
                "status": FAILED,
                "source": "local:tool-catalog",
                "reason": type(exc).__name__,
            }
        else:
            sections["runtime"] = {
                "status": COMPLETE,
                "source": "local:tool-catalog",
                "data": {"registeredTools": count},
            }
        sections["liveProbes"] = await _live(client, probes, fetchers)
        requests = counter[0]
    bundle: dict[str, Any] = {
        "bundle": "unifi-fabric-mcp-server diagnostic bundle",
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": _now(),
        "review": (
            "Review this bundle before sharing it. The server stores it nowhere and sends it "
            "to nobody: it exists only in this response."
        ),
        "collection": {
            "mode": "local+live" if probes else "local",
            "liveProbesRequested": probes,
            "liveProbesAvailable": sorted(LIVE_PROBES),
            "upstreamRequests": requests,
        },
        "sections": sections,
        "neverCollected": list(NEVER_COLLECTED),
    }
    secrets = configured_secrets(client._settings)  # noqa: SLF001 - the client's settings
    clean = scrub_json_strings(bundle, secrets)
    leaked = contains_secret(json.dumps(clean), secrets)
    clean["sanitization"] = {
        "method": "allowlist of fields, then the server's configured-secret scrubber",
        "configuredSecretsChecked": len(secrets),
        "valuesMasked": clean != bundle,
        "status": FAILED if leaked else COMPLETE,
    }
    if leaked:
        # Fail closed: the scrubber left a secret form; return no section data at all.
        clean["sections"] = {
            name: {"status": FAILED, "source": s.get("source"), "reason": "withheld"}
            for name, s in clean["sections"].items()
        }
    return clean
