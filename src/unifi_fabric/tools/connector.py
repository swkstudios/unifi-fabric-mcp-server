"""Guarded generic Fabric connector relay — GET/POST/PUT/PATCH/DELETE.

Ubiquiti's official Network Cloud Connector (and the Site Manager v1.0 OpenAPI)
document a generic method relay family:

    GET    /v1/connector/consoles/{id}/*path
    POST   /v1/connector/consoles/{id}/*path
    PUT    /v1/connector/consoles/{id}/*path
    PATCH  /v1/connector/consoles/{id}/*path
    DELETE /v1/connector/consoles/{id}/*path

The relay forwards the request through Fabric to the console's ``/proxy/<path>``
surface. Every typed tool in this server already rides that same connector; this
module exposes the relay *directly* so a caller can reach a controller-supported
route that has no typed wrapper yet (e.g. a per-device Classic REST config route,
or a legacy InnerSpace save route) — under explicit guards.

Guard model (all enforced here, none optional):

* **Registry-only identity.** The tool surface never accepts a raw console/host id
  or an API key. ``host`` (name or id) resolves to the owning key + host id through
  the Registry; a ``site`` name/UUID resolves to a slug or UUID and is substituted
  into ``{site}`` / ``{site_id}`` placeholders in the path. The raw site value never
  appears on the tool surface.
* **Positive namespace allowlist.** Only approved UniFi application proxy namespaces
  are reachable (Network integration/classic/v2, Protect integration/private,
  InnerSpace integration/legacy, Access). The allowlist is *path hygiene* — it keeps
  the relay pointed at UniFi surfaces and off arbitrary URLs — not a capability cap.
* **Positive-charset path validation.** ``..``, ``%`` (any percent-encoding),
  ``\\``, whitespace, control characters, ``//`` empty segments and a scheme (``://``)
  are rejected. This is the InnerSpace-allowlist lesson applied to the relay.
* **Mutation gating (fail-closed).** GET is always available. POST/PUT/PATCH/DELETE
  require BOTH ``confirm=true`` AND the ``UNIFI_ENABLE_CONNECTOR_WRITE`` env flag
  (code default OFF). Either missing → the mutation is refused before any network
  call is made.
* **Read-before / write / read-after.** For PUT/PATCH/DELETE (routes with a GET twin)
  the current representation is captured before the write and re-read after, with
  diff-based no-op detection so a same-value write is visibly flagged ``noOp: true``.
* **Scope guard.** ``scope`` (``device`` / ``site`` / ``global``), when supplied, is
  cross-checked against the path so a site-global setting route cannot be selected for
  a device-scoped request (and vice versa).
* **Credential redaction.** Credential-bearing fields in the relayed body are redacted
  before the body is returned or logged, and the API key value is never logged.
* **Structured audit.** Every mutation attempt is logged (console, site, method, path,
  confirm, outcome) — never the key value.

Undocumented legacy routes reached through this relay remain **experimental** until
persistence and rollback are proven against a live console in a maintenance window.
This module does not perform any live mutation on its own.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..client import UniFiClient, UniFiConnectionError
from ..config import APIKeyConfig
from ..registry import Registry

_logger = logging.getLogger(__name__)

#: Relay base. The caller-supplied ``path`` is appended after ``/proxy/``.
_RELAY_BASE = "/v1/connector/consoles/{host_id}/proxy/"

#: Positive namespace allowlist (BROAD, per the max-open-access directive). Each
#: entry is a leading-segment pattern matched against the normalized path; a site
#: segment is a single-segment wildcard so both the ``{site}`` placeholder and an
#: already-resolved slug match. The label is the returned ``routeClass``.
_ALLOWLIST: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"network/integration/v1(/|$)"), "network-integration"),
    (re.compile(r"network/api/s/[^/]+/rest(/|$)"), "network-classic-rest"),
    (re.compile(r"network/api/s/[^/]+/cmd(/|$)"), "network-classic-cmd"),
    (re.compile(r"network/api/s/[^/]+/stat(/|$)"), "network-classic-stat"),
    (re.compile(r"network/v2/api(/|$)"), "network-v2"),
    (re.compile(r"protect/integration/v1(/|$)"), "protect-integration"),
    (re.compile(r"protect/api(/|$)"), "protect-private"),
    (re.compile(r"innerspace/integration/v1(/|$)"), "innerspace-integration"),
    (re.compile(r"innerspace/api(/|$)"), "innerspace-legacy"),
    (re.compile(r"access/integration/v1(/|$)"), "access-integration"),
    (re.compile(r"access/api(/|$)"), "access-private"),
]

#: Raw (pre-substitution) path charset: alphanumerics, ``._~:-``, ``/`` separators,
#: and ``{}`` for the site placeholders. Anything else is rejected outright.
_RAW_PATH_RE = re.compile(r"^[A-Za-z0-9._~:{}/-]+$")

#: Final (post-substitution) path charset: same, minus the braces (a leftover brace
#: means an unresolved placeholder).
_FINAL_PATH_RE = re.compile(r"^[A-Za-z0-9._~:/-]+$")

#: Keys whose values are credential-bearing and must be redacted before return/log.
_CRED_KEY_RE = re.compile(
    r"(password|passphrase|secret|psk|private[-_]?key|api[-_]?key|x_ca_|token)",
    re.IGNORECASE,
)

#: Path markers used by the scope guard.
_DEVICE_MARKERS = ("/rest/device", "/stat/device")
_GLOBAL_SETTING_MARKERS = ("/rest/setting", "/set/setting", "global_switch")

_MUTATION_METHODS = ("POST", "PUT", "PATCH", "DELETE")
#: Methods with a GET twin at the same resource path (read-before / read-after).
_TWIN_METHODS = ("PUT", "PATCH", "DELETE")

_MAX_BODY_CHARS = 4000


def _check_raw_charset(path: str) -> None:
    """Positive-charset validation on the caller-supplied path template.

    Rejects the traversal / encoding / injection classes the InnerSpace allowlist
    lesson calls out, before any namespace or Registry work happens.
    """
    if "://" in path:
        raise ValueError(
            f"Invalid connector path {path!r}: must be a relay-relative path, not a URL"
        )
    if ".." in path:
        raise ValueError(f"Invalid connector path {path!r}: path traversal ('..') is not allowed")
    if "%" in path:
        raise ValueError(
            f"Invalid connector path {path!r}: percent-encoding is not allowed "
            "(pass a plain, already-decoded path)"
        )
    if "//" in path.strip("/"):
        raise ValueError(
            f"Invalid connector path {path!r}: empty path segment ('//') is not allowed"
        )
    if not _RAW_PATH_RE.match(path.strip("/")):
        raise ValueError(
            f"Invalid connector path {path!r}: only letters, digits, '. _ ~ : - /' and the "
            "'{site}'/'{site_id}' placeholders are allowed"
        )


def _match_namespace(normalized: str) -> str:
    """Return the routeClass for an allowlisted namespace, else raise ValueError."""
    for pattern, route_class in _ALLOWLIST:
        if pattern.match(normalized):
            return route_class
    allowed = ", ".join(sorted({label for _p, label in _ALLOWLIST}))
    raise ValueError(
        f"Connector path {normalized!r} is outside the approved namespace allowlist. "
        f"Allowed route classes: {allowed}. The allowlist is path hygiene, not a "
        "capability restriction — extend it in tools/connector.py if a new documented "
        "UniFi application namespace is needed."
    )


def _check_scope(normalized: str, scope: str | None) -> None:
    """Reject a device/global scope that contradicts the path's route.

    Prevents a site-global setting route from being driven by a device-scoped
    request (and the reverse). No-op when ``scope`` is not supplied.
    """
    if scope is None:
        return
    scope_l = scope.strip().lower()
    if scope_l not in ("device", "site", "global"):
        raise ValueError(f"Invalid scope {scope!r}: expected 'device', 'site', or 'global'")
    is_device_path = any(m in normalized for m in _DEVICE_MARKERS)
    is_global_path = any(m in normalized for m in _GLOBAL_SETTING_MARKERS)
    if scope_l == "device" and is_global_path:
        raise ValueError(
            f"scope='device' but path {normalized!r} targets a site-global setting route. "
            "Global switch settings (e.g. global_switch.stp_version) are site-wide; do not "
            "drive them through a device-scoped request."
        )
    if scope_l in ("site", "global") and is_device_path:
        raise ValueError(
            f"scope={scope_l!r} but path {normalized!r} targets a device-scoped route "
            "(/rest/device or /stat/device). Use scope='device' for per-device config."
        )


def _validate_relay_path(path: str, scope: str | None) -> str:
    """Full pre-network validation. Returns the resolved routeClass."""
    if not path or not path.strip():
        raise ValueError("'path' must not be empty")
    _check_raw_charset(path)
    normalized = path.strip().strip("/")
    route_class = _match_namespace(normalized)
    _check_scope(normalized, scope)
    return route_class


async def _substitute_site(
    path: str,
    site: str | None,
    host_id: str,
    registry: Registry,
    key: APIKeyConfig | None,
) -> str:
    """Substitute ``{site}`` (slug) / ``{site_id}`` (UUID) via the Registry."""
    normalized = path.strip().strip("/")
    needs_slug = "{site}" in normalized
    needs_uuid = "{site_id}" in normalized
    if needs_slug or needs_uuid:
        if not site or not site.strip():
            raise ValueError(
                "path contains a site placeholder ('{site}' or '{site_id}') but no 'site' "
                "was provided. Pass the site name or UUID; the server resolves it."
            )
        if needs_uuid:
            site_id = await registry.resolve_site_id(site, host_id, key=key)
            normalized = normalized.replace("{site_id}", site_id)
        if needs_slug:
            slug = await registry.resolve_site_slug(site, host_id, key=key)
            normalized = normalized.replace("{site}", slug)
    return normalized


def _check_final_charset(final_path: str) -> None:
    """Post-substitution guard: no leftover placeholder, traversal, or bad charset."""
    if "{" in final_path or "}" in final_path:
        raise ValueError(
            f"Unresolved placeholder in resolved path {final_path!r} — a '{{site}}'/'{{site_id}}' "
            "token remained after resolution"
        )
    if ".." in final_path or "//" in final_path.strip("/"):
        raise ValueError(f"Invalid resolved path {final_path!r}: traversal or empty segment")
    if not _FINAL_PATH_RE.match(final_path):
        raise ValueError(
            f"Invalid resolved path {final_path!r}: disallowed characters after resolution"
        )


def _redact_credentials(value: Any) -> Any:
    """Recursively redact credential-bearing field *values* in a relayed body.

    A key whose name matches the credential pattern (password/passphrase/secret/psk/
    private key/api key/token/CA) has its value replaced with ``"[REDACTED]"``.
    Non-credential values pass through verbatim (the server is a faithful access
    layer — device config, UUIDs, etc. are not withheld). Redaction is deterministic,
    so equality-based no-op detection is unaffected for non-credential changes.
    """
    if isinstance(value, dict):
        return {
            k: (
                "[REDACTED]"
                if isinstance(k, str) and _CRED_KEY_RE.search(k)
                else _redact_credentials(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_credentials(item) for item in value]
    return value


def _decode_relay_body(resp: Any) -> Any:
    """Decode the upstream response body, redacted. JSON when possible, else text."""
    try:
        data = resp.json()
    except Exception:
        text = getattr(resp, "text", "") or ""
        return {"text": text[:_MAX_BODY_CHARS]}
    return _redact_credentials(data)


async def _safe_get(client: UniFiClient, url: str, key: APIKeyConfig | None) -> dict[str, Any]:
    """Best-effort GET of a relay URL for read-before/after. Never raises."""
    try:
        resp = await client.request("GET", url, key=key, raise_on_error=False)
    except UniFiConnectionError as exc:
        return {"status": None, "error": str(exc)}
    return {"status": resp.status_code, "body": _decode_relay_body(resp)}


def _audit_mutation(
    host: str,
    site: str | None,
    method: str,
    path: str,
    confirm: bool,
    outcome: str,
    status: int | None,
) -> None:
    """Structured audit line for a mutation attempt. Never logs the API key."""
    _logger.info(
        "connector-relay-audit host=%s site=%s method=%s path=%s confirm=%s outcome=%s status=%s",
        host,
        site if site is not None else "-",
        method,
        path,
        confirm,
        outcome,
        status if status is not None else "-",
    )


def _outcome(status: int | None) -> str:
    if status is None:
        return "no_response"
    if 200 <= status < 300:
        return "success"
    return f"http_{status}"


async def connector_get(
    client: UniFiClient,
    registry: Registry,
    host: str,
    path: str,
    *,
    site: str | None = None,
    params: dict[str, Any] | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a GET through the Fabric connector. Always available (no confirm).

    Returns the upstream status and (redacted) body plus the resolved route class.
    A 4xx/5xx is reported as ``status`` rather than raised — a GET probe of an
    unknown route surfaces its own status.
    """
    route_class = _validate_relay_path(path, scope)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    final_path = await _substitute_site(path, site, host_id, registry, key)
    _check_final_charset(final_path)
    url = _RELAY_BASE.format(host_id=host_id) + final_path
    resp = await client.request("GET", url, key=key, params=params, raise_on_error=False)
    status = resp.status_code
    _logger.debug(
        "connector-relay-get host=%s site=%s path=%s outcome=%s",
        host,
        site if site is not None else "-",
        path,
        _outcome(status),
    )
    return {
        "method": "GET",
        "routeClass": route_class,
        "scope": scope,
        "path": path,
        "resolvedPath": final_path,
        "status": status,
        "body": _decode_relay_body(resp),
    }


async def connector_write(
    client: UniFiClient,
    registry: Registry,
    host: str,
    method: str,
    path: str,
    *,
    site: str | None = None,
    body: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
    write_enabled: bool = False,
) -> dict[str, Any]:
    """Relay a mutating method (POST/PUT/PATCH/DELETE) through the Fabric connector.

    Fail-closed gating: the mutation is refused — before any network call — unless
    BOTH ``write_enabled`` (the ``UNIFI_ENABLE_CONNECTOR_WRITE`` env flag) is set AND
    ``confirm=True``. For PUT/PATCH/DELETE the resource is read before and after the
    write with diff-based no-op detection. The upstream status/body (redacted) and the
    resolved route class are returned; a 4xx/5xx is reported, not raised, so an
    invalid-ID probe surfaces its reachability status.
    """
    method_u = method.strip().upper()
    if method_u not in _MUTATION_METHODS:
        raise ValueError(f"connector_write does not handle {method_u!r}; use connector_get for GET")
    # 1) Path/namespace/scope validation and 2) gating happen with NO network calls,
    #    so a rejected mutation never touches the console or resolves a key.
    route_class = _validate_relay_path(path, scope)
    if not write_enabled:
        raise ValueError(
            f"{method_u} connector relay is disabled. Connector writes are OFF by default; "
            "set UNIFI_ENABLE_CONNECTOR_WRITE=1 in the server environment to enable them. "
            "GET relay is always available."
        )
    if not confirm:
        raise ValueError(
            f"{method_u} connector relay is a mutation and requires confirm=true. "
            "Re-issue with confirm=true once you have verified the console, path, and body."
        )

    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    final_path = await _substitute_site(path, site, host_id, registry, key)
    _check_final_charset(final_path)
    url = _RELAY_BASE.format(host_id=host_id) + final_path

    read_before: dict[str, Any] | None = None
    if method_u in _TWIN_METHODS:
        read_before = await _safe_get(client, url, key)

    try:
        resp = await client.request(method_u, url, key=key, json=body, raise_on_error=False)
        status: int | None = resp.status_code
        resp_body = _decode_relay_body(resp)
    except UniFiConnectionError as exc:
        _audit_mutation(host, site, method_u, path, confirm, "error", None)
        raise UniFiConnectionError(f"Connector {method_u} relay failed: {exc}") from exc

    read_after: dict[str, Any] | None = None
    if method_u in _TWIN_METHODS:
        read_after = await _safe_get(client, url, key)

    no_op: bool | None = None
    if read_before is not None and read_after is not None:
        before_body = read_before.get("body")
        after_body = read_after.get("body")
        if "body" in read_before and "body" in read_after:
            no_op = before_body == after_body

    outcome = _outcome(status)
    _audit_mutation(host, site, method_u, path, confirm, outcome, status)

    result: dict[str, Any] = {
        "method": method_u,
        "routeClass": route_class,
        "scope": scope,
        "path": path,
        "resolvedPath": final_path,
        "status": status,
        "body": resp_body,
        "confirmed": confirm,
        "writeEnabled": write_enabled,
    }
    if method_u in _TWIN_METHODS:
        result["readBefore"] = read_before
        result["readAfter"] = read_after
        result["noOp"] = no_op
        if no_op is not None:
            result["changed"] = not no_op
    return result
