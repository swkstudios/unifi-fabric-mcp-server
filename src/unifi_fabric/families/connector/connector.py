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
  into ``{site}`` / ``{site_id}`` placeholders in the path; the result's ``resolvedPath``
  reports the path as sent, substituted site included. ``path`` and ``resolvedPath`` are
  relative to the console's ``/proxy/``, so neither carries the console id or the key.
* **Route classes (a route-to-area map, not a gate).** Known UniFi application proxy
  namespaces (Network integration / Classic ``network/api`` / v2, Protect
  integration/private, InnerSpace integration/legacy, Access) map to a ``routeClass``. Each
  entry admits a whole application namespace — every Classic ``network/api`` route
  (``api/s/{site}/rest``, ``cmd``, ``stat``, ``set/setting``, ``upd``, ``list``, ``group``,
  ``api/self``, ``api/stat/sites`` ...) included — so a per-area write opt-out binds every
  route of its area. A valid path in no listed namespace (``talk/``, ``connect/``,
  ``drive/`` ...) relays with ``routeClass: "unclassified"``: a GET always, a mutation
  unless a per-area write opt-out is active (its area cannot be proven, so it is then
  refused naming the active variable or variables). Not a capability cap.
* **Positive-charset path validation.** ``..``, ``%`` (any percent-encoding),
  ``\\``, whitespace, control characters, ``//`` empty segments and a scheme (``://``)
  are rejected. This is the InnerSpace-allowlist lesson applied to the relay.
* **Mutation gating (read + write on by default).** Ordinary GET reads are always available.
  POST/PUT/PATCH/DELETE and known state-changing GETs are gated by the
  ``UNIFI_WRITE_EXCEPTIONS`` entry ``family:connector=deny``; writes are
  ENABLED by default, and the ``confirm`` argument is accepted for compatibility and no longer
  required. A mutation is refused only when that entry is set, or ``UNIFI_WRITE_POLICY=deny``,
  for a read-only deployment. A refused mutation is rejected before any
  network call is made.
* **Per-area opt-outs.** A mutation on a route class that belongs to an area with its
  own write opt-out (``network-*`` routes: ``family:network=deny``;
  ``protect-*`` routes: ``family:protect=deny``; the
  Mobility and Carrier Fabric opt-outs likewise for any ``mobility-*`` / ``carrier-*``
  route class) is refused before any network call when that opt-out is set, exactly as
  the area's typed tools are. See :data:`_AREA_OPT_OUTS`. The client chokepoint
  (``read_only.guard_area_write``) refuses the same writes by route as the last layer.
  A mutation on an ``unclassified`` route is refused while ANY per-area opt-out is set.
* **No 429 auto-retry on a mutation.** A relayed POST/PUT/PATCH/DELETE or known
  state-changing GET is sent once (only reads via GET are retried) and a 429 is surfaced: the relay
  cannot tell a physical action (a siren, a relay output, a Classic ``cmd``) from a
  settings write, and a retry can repeat the action. The 429 is raised
  (``RateLimitError``, with the upstream body) and audited. The read-before /
  read-after GETs keep the GET retry.
* **Read-before / write / read-after.** For PUT/PATCH/DELETE (routes with a GET twin)
  the current representation is captured before the write and re-read after, with
  diff-based no-op detection so a same-value write is visibly flagged ``noOp: true``.
  An object body is compared over the leaves it requests only (unrequested siblings
  never count); a body-less write compares the whole reads. A DELETE is ``noOp: false``
  (deleted) only when the read-after answers 404; otherwise ``noOp`` is null and
  ``noOpReason`` (or ``readAfterError``) says why. The Classic ``rest/device/<_id>``
  route has no GET (the controller answers 404), so a PUT/PATCH there reads the site's
  full ``stat/device`` list in ``readBefore``/``readAfter.body``; ``comparisonRecords``
  holds the matched device records, and the verdict compares only the leaves the body
  writes (live statistics change between any two reads). ``noOpBasis`` explains this
  comparison; ``twin`` names the GET twin and ``twinError`` explains resolution failures.
* **Scope guard.** ``scope`` (``device`` / ``site`` / ``global``), when supplied, is
  cross-checked against the path so a site-global setting route cannot be selected for
  a device-scoped request (and vice versa).
* **Verbatim bodies.** The relayed upstream body is returned unchanged (JSON decoded when
  possible, otherwise the full response text) — the pass-through invariant in
  ``CLAUDE.md``. A text body is decoded with its declared ``charset`` when Python knows
  that codec (``latin-1``, ``windows-1252``, ``utf-16`` ...; UTF-8 otherwise). A binary
  body (a non-text Content-Type such as ``image/jpeg``, or bytes that do not decode
  strictly under that charset) cannot survive a text decode, so it is returned the way
  the typed binary tools return bytes: complete and uncapped, base64 encoded under
  ``bodyBase64`` with ``sizeBytes`` and ``body`` null. Every relayed body
  (the write's own response and its read-before / read-after) carries the upstream
  ``contentType``. Credential masking is the server-wide opt-in ``UNIFI_REDACT_SECRETS``
  (``redaction.py``), which covers this relay like every other tool; it is OFF by default.
  Bodies are never logged, and the API key value is never logged.
* **Route secrets.** A route listed in :data:`unifi_fabric.route_secrets.ROUTE_SECRETS` (the
  Matter ``setup_code``, a Protect camera share link) is protected exactly as its typed
  tool protects it: every confirmed registered secret (request field, response field,
  redirect ``Location``) is always scrubbed from logs and the audit log, and from dry-run
  previews, errors and non-2xx relay results only with UNIFI_REDACT_SECRETS. A successful
  upstream body is still returned verbatim.
* **Structured audit.** Every mutation attempt is logged (console, site, method, path,
  confirm, outcome) — never the key value.

Undocumented legacy routes reached through this relay remain **experimental** until
persistence and rollback are proven against a live console in a maintenance window.
This module does not perform any live mutation on its own.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from collections.abc import Callable
from contextvars import ContextVar
from typing import Annotated, Any, overload

from fastmcp import FastMCP
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from pydantic import WithJsonSchema

from ... import switches
from ..._read_only_audit import state_changing_get
from ...client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    classic_rc_error,
    content_type_charset,
    decode_body,
    object_records,
    strip_additive_keys,
    text_codec,
    upstream_error_text,
    v2_error_envelope,
)
from ...config import APIKeyConfig
from ...matching import same_id
from ...read_only import (
    ReadOnlyModeError,
    decoded_path,
    guard_action,
    is_write_request,
    mark_write_denied,
    state_changing_get_route,
)
from ...registry import Registry
from ...request_policy import request_dry_run_active
from ...route_secrets import (
    mask_request_path,
    mask_response_body,
    matching,
    request_path_secrets,
    response_secrets,
)
from ...secret_scrub import configured_secrets, scrub, scrub_bytes, scrub_json_strings
from ...shared_shapes._results import MISSING, leaf_equal, with_read_after_error
from ...tool_annotations import WRITE
from ...write_body import require_unmasked_fields
from ..carrier import carrier_fabric
from ..mobility import mobility
from ..protect import protect

_logger = logging.getLogger(__name__)


# Presence comes from raw MCP arguments, before defaults are populated: an omitted
# optional body remains absent on the wire, while an explicit JSON null is sent.
#: A free-form JSON value: the relay sends whatever the caller gives it, verbatim, so the
#: ``body`` of a relayed mutation is an object, array, string, number, boolean or null,
#: at any nesting. Validation stays ``Any`` (every shape passes through unchanged); the
#: published schema is a flat, NON-recursive union whose every branch carries a ``type``
#: and which has no ``$ref``/``$defs`` and no empty ``{}`` subschema.
type RelayBody = Annotated[
    Any,
    WithJsonSchema(
        {
            "anyOf": [
                {"type": "object"},
                {"type": "array"},
                {"type": "string"},
                {"type": "number"},
                {"type": "boolean"},
                {"type": "null"},
            ]
        }
    ),
]

_explicit_null_body: ContextVar[bool] = ContextVar("relay_explicit_null_body", default=False)


class RelayBodyPresenceMiddleware(Middleware):
    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        name = str(getattr(context.message, "name", ""))
        args = getattr(context.message, "arguments", None) or {}
        present = (
            name
            in {
                "fabric_connector_post",
                "fabric_connector_put",
                "fabric_connector_patch",
                "fabric_connector_delete",
            }
            and "body" in args
            and args["body"] is None
        )
        token = _explicit_null_body.set(present)
        try:
            return await call_next(context)
        finally:
            _explicit_null_body.reset(token)


#: Relay base. The caller-supplied ``path`` is appended after ``/proxy/``.
_RELAY_BASE = "/v1/connector/consoles/{host_id}/proxy/"

#: Route-class map (BROAD, per the max-open-access directive; a path in no entry is
#: :data:`UNCLASSIFIED`, not refused). Each
#: entry is a leading-segment pattern matched against the normalized path; a site
#: segment is a single-segment wildcard so both the ``{site}`` placeholder and an
#: already-resolved slug match. The label is the returned ``routeClass``.
_ALLOWLIST: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"network/integration/v1(/|\Z)"), "network-integration"),
    (re.compile(r"network/api/s/[^/]+/rest(/|\Z)"), "network-classic-rest"),
    (re.compile(r"network/api/s/[^/]+/cmd(/|\Z)"), "network-classic-cmd"),
    (re.compile(r"network/api/s/[^/]+/stat(/|\Z)"), "network-classic-stat"),
    # Every other Classic route: api/s/{site}/set/setting/<key>, upd/, list/, group/ ...,
    # and the controller-level api/self, api/stat/sites. Same Classic REST surface the
    # typed tools ride; no route of it is withheld from the relay.
    (re.compile(r"network/api/s/[^/]+/[^/]+"), "network-classic"),
    (re.compile(r"network/api(/|\Z)"), "network-classic-controller"),
    (re.compile(r"network/v2/api(/|\Z)"), "network-v2"),
    (re.compile(r"protect/integration/v1(/|\Z)"), "protect-integration"),
    (re.compile(r"protect/api(/|\Z)"), "protect-private"),
    (re.compile(r"innerspace/integration/v1(/|\Z)"), "innerspace-integration"),
    (re.compile(r"innerspace/api(/|\Z)"), "innerspace-legacy"),
    (re.compile(r"access/integration/v1(/|\Z)"), "access-integration"),
    (re.compile(r"access/api(/|\Z)"), "access-private"),
]

#: Raw (pre-substitution) path charset: alphanumerics, ``._~:-``, ``/`` separators,
#: and ``{}`` for the site placeholders. Anything else is rejected outright.
_RAW_PATH_RE = re.compile(r"^[A-Za-z0-9._~:{}/-]+\Z")

#: Final (post-substitution) path charset: same, minus the braces (a leftover brace
#: means an unresolved placeholder).
_FINAL_PATH_RE = re.compile(r"^[A-Za-z0-9._~:/-]+\Z")

#: Route classes the scope guard reads, as the leading resource segments of the route
#: (the part after the Classic ``api/s/<site>`` or v2 ``api/site/<site>`` prefix), so a
#: site name or an id segment is never read as a route class.
_DEVICE_ROUTES = (("rest", "device"), ("stat", "device"))
_GLOBAL_SETTING_ROUTES = (("rest", "setting"), ("set", "setting"))


def _route_segments(normalized: str) -> list[str]:
    """The resource segments of a relay path after its site prefix (the whole path when
    it has none)."""
    segments = [s for s in normalized.split("/") if s]
    for index in range(1, len(segments) - 1):
        if segments[index - 1] == "api" and segments[index] in ("s", "site"):
            return segments[index + 2 :]
    return segments


def _route_is(normalized: str, routes: tuple[tuple[str, str], ...]) -> bool:
    head = tuple(_route_segments(normalized)[:2])
    return head in routes


_MUTATION_METHODS = ("POST", "PUT", "PATCH", "DELETE")

#: The routeClass of a valid relay path in no mapped namespace (see the module docstring).
UNCLASSIFIED = "unclassified"


def _area_opt_out_text(area: str, env: str) -> str:
    """The refusal text of a denied area (``switches.area_deny_text``)."""
    return switches.area_deny_text(area, env)


#: Per-area write opt-outs the relay honours. Each entry is
#: ``(routeClass prefix, env var, enabled check, refusal reason)``: a relayed mutation
#: whose routeClass starts with the prefix is refused, before any upstream call, when
#: that area's opt-out is set, exactly as the area's typed write tools are. This enforces
#: the existing opt-outs on the relay; it is not a new gate (all default ON).
#:
#: Mobility (``/v1/mobility``) and Carrier Fabric (``/v1/carrier``) are Site Manager
#: cloud routes, not console ``/proxy/`` routes, so no allowlisted routeClass reaches
#: them today (the relay base is pinned to ``/v1/connector/consoles/{id}/proxy/``).
#: Their entries keep the rule total: a routeClass added later under either prefix is
#: gated automatically. ``tests/test_cross_tool_invariants.py`` (invariant ``bn``)
#: requires every per-area opt-out to be listed here.
#: Built from ``switches.AREA_WRITE_SWITCHES`` (the one table of area opt-outs), so the
#: relay parses and honours each switch exactly as the area's typed tools do.
_AREA_REASONS: dict[str, str] = {
    switches.NETWORK_WRITES.env: _area_opt_out_text("Network", switches.NETWORK_WRITES.env),
    protect.PROTECT_MUTATIONS_ENV: protect.MUTATIONS_DISABLED_REASON,
    mobility.WRITE_ENABLED_ENV: mobility.DISABLED_MSG,
    carrier_fabric.WRITE_ENABLED_ENV: carrier_fabric.DISABLED_MSG,
    switches.INNERSPACE_WRITES.env: _area_opt_out_text(
        "InnerSpace", switches.INNERSPACE_WRITES.env
    ),
}
_AREA_OPT_OUTS: tuple[tuple[str, str, Callable[[], bool], str], ...] = tuple(
    (switch.relay_prefix, switch.env, switch.enabled, _AREA_REASONS[switch.env])
    for switch in switches.AREA_WRITE_SWITCHES
)


#: The connector relay's write opt-out: the ``family:connector=deny`` write exception.
CONNECTOR_WRITE_ENV = switches.CONNECTOR_WRITE_TOKEN


def connector_write_refusal(method: str) -> str:
    """The refusal of a relayed mutation while ``family:connector=deny`` is set."""
    return f"{method} connector relay is refused. " + switches.area_deny_text(
        "Connector relay", CONNECTOR_WRITE_ENV
    )


def area_write_refusal(family: str | None) -> str | None:
    """The refusal of a typed write tool of ``family`` when its area opts out, else None.

    One table (``switches.AREA_WRITE_SWITCHES``) and the area's own refusal text, so a
    tool-level refusal and the area's in-tool check say the same thing.
    """
    for switch in switches.AREA_WRITE_SWITCHES:
        if switch.governs(family) and not switch.enabled():
            return _AREA_REASONS[switch.env] + switches.current_value_note(switch.env)
    return None


def area_write_env(family: str | None) -> str | None:
    """The opt-out variable refusing ``family``'s typed write tools now, else None."""
    for switch in switches.AREA_WRITE_SWITCHES:
        if switch.governs(family) and not switch.enabled():
            return switch.env
    return None


def _opted_out_relay_env(route_class: str) -> str | None:
    """The opt-out variable refusing a relayed mutation on ``route_class`` now, else None."""
    if route_class == UNCLASSIFIED:
        return ", ".join(_active_area_opt_outs()) or None
    for prefix, env_var, enabled, _reason in _AREA_OPT_OUTS:
        if route_class.startswith(prefix) and not enabled():
            return env_var
    return None


def relay_get_opt_out_env(path: Any, scope: Any) -> str | None:
    """The write opt-out refusing ``fabric_connector_get`` on ``path`` now, else None.

    In the order :func:`fabric_connector_get` checks them: a path that is not a
    state-changing route, or that fails validation, has none; then
    ``family:connector=deny``, then the route's area switch. Read-only mode is not
    included (its refusal is audited where it is raised). Makes no network call.
    """
    if not isinstance(path, str) or not is_write_request("GET", path):
        return None
    if scope is not None and not isinstance(scope, str):
        return None
    try:
        route_class = _validate_relay_path(path, scope)
    except ValueError:
        return None
    if not switches.connector_writes_enabled():
        return CONNECTOR_WRITE_ENV
    return _opted_out_relay_env(route_class)


def _active_area_opt_outs() -> list[str]:
    """Every per-area write opt-out variable set now (configured order)."""
    return [env_var for _prefix, env_var, enabled, _reason in _AREA_OPT_OUTS if not enabled()]


def _audit_refusal(client: Any, method: str, path: str, reason: str) -> None:
    """Audit a relayed mutation a gate refused (``outcome=refused``, ``reason`` = the
    gate's variable); a no-op for a direct caller's stand-in client and when the audit
    log is off."""
    if isinstance(client, UniFiClient):
        client.audit_refusal(
            method=method,
            path=scrub(path, configured_secrets(extra=request_path_secrets(method, path))),
            reason=reason,
        )


def _check_area_opt_out(method: str, route_class: str) -> None:
    """Refuse a relayed mutation on a route class whose area write opt-out is set.

    Raises ``ValueError`` naming the opted-out variable. Makes no network call.
    """
    for prefix, env_var, enabled, reason in _AREA_OPT_OUTS:
        if route_class.startswith(prefix) and not enabled():
            raise mark_write_denied(
                ValueError(
                    f"{method} connector relay to a {route_class} route is refused: {env_var} "
                    f"opts this area out of writes, and the relay honours it. {reason}"
                    f"{switches.current_value_note(env_var)}"
                )
            )


def _check_unclassified_mutation(method: str, route_class: str) -> None:
    """Refuse a relayed mutation on an ``unclassified`` route while any per-area write
    opt-out is set: the path's area cannot be proven, so it might be an opted-out one.

    Raises ``ValueError`` naming every active opt-out variable. Makes no network call.
    With no opt-out set the mutation relays.
    """
    if route_class != UNCLASSIFIED:
        return
    active = _active_area_opt_outs()
    if active:
        raise mark_write_denied(
            ValueError(
                f"{method} connector relay to an unclassified route is refused while a per-area "
                f"write opt-out is active ({', '.join(active)}): the path is in no mapped UniFi "
                "application namespace, so it cannot be shown to be outside the opted-out "
                "area(s). GET on this path relays; the mutation relays once the opt-out is "
                "cleared, or use the area's typed tool."
            )
        )


#: Methods with a GET twin at the same resource path (read-before / read-after).
_TWIN_METHODS = ("PUT", "PATCH", "DELETE")

#: A Classic device write (``network/api/s/<site>/rest/device/<_id>``). The controller has
#: NO GET on ``rest/device`` (404 api.err.NotFound, live-verified on Network 11.0.81), so
#: its read twin is the site's ``stat/device`` list, filtered to that device (see
#: :func:`_device_twin`).
_CLASSIC_DEVICE_WRITE_RE = re.compile(r"^(network/api/s/[^/]+)/rest/device/([^/]+)/?\Z")

#: Methods whose read twin may be remapped (a DELETE keeps its own path: its read-after
#: 404 is the expected answer).
_REMAPPED_TWIN_METHODS = ("PUT", "PATCH")


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
    """Return the routeClass of a mapped namespace, else :data:`UNCLASSIFIED`."""
    for pattern, route_class in _ALLOWLIST:
        if pattern.match(normalized):
            return route_class
    return UNCLASSIFIED


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
    is_device_path = _route_is(normalized, _DEVICE_ROUTES)
    is_global_path = _route_is(normalized, _GLOBAL_SETTING_ROUTES)
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


def _check_site_given(normalized: str, site: str | None) -> None:
    """A path with a ``{site}`` / ``{site_id}`` placeholder needs a non-empty ``site``.

    Part of the pre-network validation: it runs before the host is resolved, so the
    missing argument is reported with zero upstream requests.
    """
    if ("{site}" in normalized or "{site_id}" in normalized) and (
        not isinstance(site, str) or not site.strip()
    ):
        raise ValueError(
            "path contains a site placeholder ('{site}' or '{site_id}') but no 'site' "
            "was provided. Pass the site name or UUID; the server resolves it."
        )


#: The only placeholders the relay substitutes. Any other ``{token}`` is rejected before
#: the host is resolved, so a typo never costs an upstream request.
_ALLOWED_PLACEHOLDERS = frozenset({"{site}", "{site_id}"})
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")


def _check_placeholders(path: str) -> None:
    """Reject any placeholder other than ``{site}`` / ``{site_id}``, and stray braces.

    Part of the pre-network validation (read and write relays): it runs before the host
    is resolved, so a bad placeholder is reported with zero upstream requests.
    """
    unknown = sorted({t for t in _PLACEHOLDER_RE.findall(path) if t not in _ALLOWED_PLACEHOLDERS})
    if unknown:
        raise ValueError(
            f"Invalid connector path {path!r}: unsupported placeholder(s) {', '.join(unknown)}. "
            "Only '{site}' (site slug) and '{site_id}' (site UUID) are substituted; "
            "replace any other placeholder with its literal value."
        )
    rest = _PLACEHOLDER_RE.sub("", path)
    if "{" in rest or "}" in rest:
        raise ValueError(
            f"Invalid connector path {path!r}: unbalanced '{{' or '}}'. Only the complete "
            "placeholders '{site}' and '{site_id}' may contain braces."
        )


def _validate_relay_path(path: str, scope: str | None) -> str:
    """Full pre-network validation of the path. Returns the resolved routeClass."""
    if not path or not path.strip():
        raise ValueError("'path' must not be empty")
    _check_raw_charset(path)
    _check_placeholders(path)
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


#: Content types whose bodies are text (decoded as JSON when they parse, else returned as
#: text). Any other declared type is binary and travels base64-encoded.
_TEXT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/javascript",
        "application/ecmascript",
        "application/x-www-form-urlencoded",
        "application/x-ndjson",
        "application/yaml",
        "application/x-yaml",
    }
)


def _media_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


#: Codecs Python registers as text encodings that are NOT character sets: transforms and
#: escape decoders (``idna`` / ``punycode`` decode host labels, ``unicode_escape`` /
#: ``raw_unicode_escape`` interpret backslash escapes, ``undefined`` always fails,
#: ``charmap`` is the generic mapping machinery). A Content-Type naming one of them is
#: never used to decode a body; the body travels as ``bodyBase64`` instead. (Non-text
#: codecs such as ``rot13``, ``base64`` or ``zlib`` are excluded by ``_is_text_encoding``.)
#: Marker for a ``charset`` parameter that names no usable character set.
_UNUSABLE = "<unusable>"


def _charset_param(content_type: str) -> str | None:
    """The raw ``charset`` parameter of a Content-Type (None when there is none)."""
    return content_type_charset(content_type)


def _declared_codec(content_type: str | None) -> str | None:
    """The Python codec of the Content-Type ``charset`` parameter.

    None when the header names no charset (or an empty one); :data:`_UNUSABLE` when it
    names one that is not a real text character set: unknown to Python, a non-text codec
    (``codecs.lookup(...)._is_text_encoding`` false: ``rot13``, ``base64`` ...) or a
    transform in :data:`unifi_fabric.client.NON_CHARSET_CODECS`. Never raises.
    """
    if not content_type:
        return None
    try:
        charset = _charset_param(content_type)
        if not charset:
            return None
        codec = text_codec(charset)
    except Exception:  # anything a registered codec search raises
        return _UNUSABLE
    return codec if codec is not None else _UNUSABLE


def _is_text_media(media: str) -> bool:
    return (
        media.startswith("text/") or media.endswith(("+json", "+xml")) or media in _TEXT_MEDIA_TYPES
    )


def _decoded_text(resp: Any, content_type: str | None) -> str | None:
    """The body as text, decoded strictly, or None when it is binary.

    A declared non-text type is binary. A text or JSON type (or no Content-Type) is
    decoded with the declared ``charset`` when it names a real text character set
    (``latin-1``, ``windows-1252``, ``utf-16`` ...; see :func:`_declared_codec`), else as
    UTF-8 when no charset is declared. A charset that names no usable character set, and
    bytes that do not decode strictly under the codec (any decode error: a
    ``UnicodeError`` such as a missing UTF-16 BOM, or anything else a codec raises), make
    the body binary - never decoded lossily, never an exception.
    """
    media = _media_type(content_type)
    if media is not None and not _is_text_media(media):
        return None
    codec = _declared_codec(content_type) or "utf-8"
    if codec == _UNUSABLE:
        return None
    try:
        return bytes(resp.content).decode(codec)
    except Exception:
        return None


def _is_binary_body(resp: Any, content_type: str | None) -> bool:
    """True when the body is bytes a text decode would corrupt (see :func:`_decoded_text`).

    An empty or 204 body is never binary.
    """
    if resp.status_code == 204 or not resp.content:
        return False
    return _decoded_text(resp, content_type) is None


def _auth_hint_metadata(resp: Any) -> dict[str, str]:
    """Transport guidance stays outside the verbatim upstream body."""
    hint = getattr(resp, "extensions", {}).get("unifi_auth_hint")
    return {"_hint": hint} if isinstance(hint, str) and hint else {}


def _relay_body(resp: Any) -> dict[str, Any]:
    """The upstream body of one relayed response, verbatim and lossless.

    A text body is decoded with its declared ``charset`` when that is a codec Python
    knows (UTF-8 otherwise): JSON is parsed, other text is returned exactly as decoded, a
    204 or empty body is ``None``, all under ``body``. Every text body goes through the
    server's single decode chokepoint (``client.decode_body``). Only a body that does not
    decode strictly (or a declared non-text type) is binary: it is returned like the typed
    binary tools return bytes - the complete body base64-encoded under ``bodyBase64`` with
    ``sizeBytes`` (no size cap) and ``body`` null. ``contentType`` is the upstream
    Content-Type header (null when none was sent); no type is invented.
    """
    content_type = resp.headers.get("content-type")
    if _is_binary_body(resp, content_type):
        return _base64_body(resp)
    return {"contentType": content_type, "body": decode_body(resp), **_auth_hint_metadata(resp)}


def _base64_body(resp: Any, *, content: bytes | None = None) -> dict[str, Any]:
    """The complete body base64-encoded (``bodyBase64`` + ``sizeBytes``, ``body`` null)."""
    raw = bytes(resp.content) if content is None else content
    return {
        "contentType": resp.headers.get("content-type"),
        "body": None,
        "bodyBase64": base64.b64encode(raw).decode("ascii"),
        "sizeBytes": len(raw),
        **_auth_hint_metadata(resp),
    }


def _route_fallback_body(
    client: UniFiClient, method: str, path: str, resp: Any, *, failed: bool = False
) -> dict[str, Any]:
    """Apply configured-secret scrubbing; route redaction follows the opt-in."""
    redact = getattr(getattr(client, "_settings", None), "redact_secrets", False) is True
    content_type = resp.headers.get("content-type")
    text = _decoded_text(resp, content_type) if redact or failed else None
    secrets = (
        configured_secrets(getattr(client, "_settings", None), include_call=False) if failed else ()
    )
    if text is None:
        # An undecodable registered-route body cannot safely expose opaque bytes.
        if failed and redact and (matching(method, path) or matching("GET", path)):
            return _base64_body(resp, content=b"***")
        return _base64_body(resp, content=scrub_bytes(bytes(resp.content), secrets))
    bom = "\ufeff" if text.startswith("\ufeff") else ""
    try:
        body = json.loads(text.removeprefix(bom) if bom else text)
        is_json = True
    except ValueError:
        body, is_json = text, False
    clean = mask_response_body(method, path, body, redact_secrets=redact)
    if failed:
        route_values: tuple[str, ...] = ()
        if redact:
            route_values = (
                *response_secrets(method, path, resp.content, resp.headers.items()),
                *response_secrets("GET", path, resp.content, resp.headers.items()),
            )
        secrets = configured_secrets(
            getattr(client, "_settings", None), extra=route_values, include_call=False
        )
        clean = scrub_json_strings(clean, secrets)
    if clean == body:
        return _base64_body(resp)
    output = bom + json.dumps(clean, separators=(",", ":")) if is_json else clean
    return _base64_body(resp, content=output.encode(_declared_codec(content_type) or "utf-8"))


#: Response headers never echoed back on a relayed redirect (credentials and cookies).
_UNSAFE_HEADERS = frozenset(
    {"set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key"}
)


def _redirect_headers(client: UniFiClient, resp: Any, key: APIKeyConfig | None) -> dict[str, Any]:
    """``{"headers": {...}}`` for a 3xx relay response, else ``{}``.

    A redirect is never followed, so where it points (``Location``) and the rest of its
    response headers are the result: every header is returned except credentials and
    cookies (:data:`_UNSAFE_HEADERS`), each value scrubbed of configured secrets and,
    under ``UNIFI_REDACT_SECRETS``, of the call's bound route secrets (a redirect is a
    failed result, never a 2xx body).
    """
    status = getattr(resp, "status_code", None)
    if not isinstance(status, int) or not 300 <= status < 400:
        return {}
    headers = {
        name: client._scrub(value, key)
        for name, value in resp.headers.items()
        if name.lower() not in _UNSAFE_HEADERS
    }
    return {"headers": headers}


#: The additive key a relayed Classic response carries when it is not a success: HTTP 2xx
#: without ``meta.rc == "ok"`` (:func:`client.classic_rc_error`). The relay reports an
#: upstream error status rather than raising it, so a Classic error answered with HTTP 200
#: is reported the same way: ``status`` and ``body`` stay verbatim and this marker says
#: why the response is an error, on the write and on ``readBefore`` / ``readAfter``.
CLASSIC_RC_ERROR_KEY = "_classicRcError"

#: The additive key a relayed Network v2 response carries when it is HTTP 2xx whose body is
#: a bare ``{"error": {"code", "message"}}`` envelope (:func:`client.v2_error_envelope`):
#: the console refused the request inside a 200. Same contract as the Classic marker:
#: ``status`` and ``body`` verbatim, the reason here, no ``noOp`` / ``changed`` verdict.
UPSTREAM_ERROR_KEY = "_upstreamError"

#: Audit outcome of a relayed response, by the marker it carries.
_MARKER_OUTCOMES = {
    CLASSIC_RC_ERROR_KEY: "classic_rc_error",
    UPSTREAM_ERROR_KEY: "upstream_error_body",
}


def _classic_rc_marker(url: str, status: Any, body: Any) -> dict[str, str]:
    """The error marker of a 2xx response that is an upstream error, else ``{}``.

    ``{"_classicRcError": reason}`` for a Classic route without ``rc == "ok"``;
    ``{"_upstreamError": reason}`` for a Network v2 route answering a bare ``error`` object.
    """
    reason = classic_rc_error(url, status, body)
    if reason is not None:
        return {CLASSIC_RC_ERROR_KEY: reason}
    reason = v2_error_envelope(url, status, body)
    return {UPSTREAM_ERROR_KEY: reason} if reason is not None else {}


def _marker_outcome(marker: dict[str, str], status: Any) -> str:
    """The audit outcome of a relayed response carrying ``marker`` (else by ``status``)."""
    for key, outcome in _MARKER_OUTCOMES.items():
        if key in marker:
            return outcome
    return _outcome(status)


def _read_ok(read: dict[str, Any] | None) -> bool:
    """A relay read that returned its resource: HTTP 2xx and no error marker (Classic
    ``meta.rc == "ok"``; no bare v2 ``error`` envelope)."""
    return (
        read is not None
        and _is_2xx(read.get("status"))
        and not any(key in read for key in _MARKER_OUTCOMES)
    )


@overload
def _route_response(
    client: UniFiClient, method: str, path: str, result: dict[str, Any]
) -> dict[str, Any]: ...
@overload
def _route_response(client: UniFiClient, method: str, path: str, result: None) -> None: ...
@overload
def _route_response(
    client: UniFiClient, method: str, path: str, result: dict[str, Any] | None
) -> dict[str, Any] | None: ...
def _route_response(
    client: UniFiClient, method: str, path: str, result: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Mask only the emitted body under the opt-in; comparisons keep raw GET evidence.

    Configured server secrets were already scrubbed by the client. Bound route values
    are redacted only under the opt-in. Preserve every metadata field and use the registry
    for JSON fields and whole text bodies.
    """
    if result is None or "body" not in result:
        return result
    redact = getattr(getattr(client, "_settings", None), "redact_secrets", False) is True
    body = mask_response_body(method, path, result["body"], redact_secrets=redact)
    return result if body is result["body"] else {**result, "body": body}


def _failed_write_result(
    client: UniFiClient, method: str, path: str, result: dict[str, Any]
) -> dict[str, Any]:
    """Every part of a failed/partial write is an error, including successful twins.

    Match both the write and GET registry entries: some secret routes register only
    one method. Bound values join the result only under the opt-in redaction policy.
    Raw twin evidence used for the no-op comparison is never changed.
    """
    redact = getattr(getattr(client, "_settings", None), "redact_secrets", False) is True
    values: list[str] = list(request_path_secrets(method, path)) if redact else []
    # Copy emitted envelopes; raw evidence remains available to callers/comparisons.
    result = dict(result)
    for name in ("readBefore", "readAfter"):
        if isinstance(result.get(name), dict):
            result[name] = dict(result[name])
    for response in (result, result.get("readBefore"), result.get("readAfter")):
        if not isinstance(response, dict) or "body" not in response:
            continue
        if (
            response is not result
            and "bodyBase64" in response
            and redact
            and (matching(method, path) or matching("GET", path))
        ):
            response["bodyBase64"] = base64.b64encode(b"***").decode("ascii")
            response["sizeBytes"] = 3
        content = json.dumps(response["body"]).encode("utf-8")
        headers = (("content-type", "application/json"), *response.get("headers", {}).items())
        if redact:
            for verb in {method, "GET"}:
                values.extend(response_secrets(verb, path, content, headers))
    return scrub_json_strings(
        result,
        configured_secrets(getattr(client, "_settings", None), extra=values, include_call=False),
    )


def _read_after_error(
    client: UniFiClient, read_after: dict[str, Any] | None, method: str = "GET"
) -> str | None:
    """Why a relay read did not return the resource, or None when it did.

    After a DELETE a 404 is the expected answer (the resource is gone), not a failure.
    """
    if read_after is None:
        return None
    secrets = configured_secrets(
        getattr(client, "_settings", None),
        include_call=bool(getattr(getattr(client, "_settings", None), "redact_secrets", False)),
    )
    if "error" in read_after:
        return scrub(str(read_after["error"]), secrets)
    for marker_key, label in ((CLASSIC_RC_ERROR_KEY, "Classic"), (UPSTREAM_ERROR_KEY, "Upstream")):
        if read_after.get(marker_key):
            body = read_after.get("body")
            return scrub(
                f"{label} error on the read-after GET: {read_after[marker_key]}"
                + (f": {upstream_error_text(body, client)}" if body is not None else ""),
                secrets,
            )
    if read_after.get("twinError"):
        return scrub(str(read_after["twinError"]), secrets)
    status = read_after.get("status")
    if method == "DELETE" and status == 404:
        return None
    if isinstance(status, int) and not 200 <= status < 300:
        body = read_after.get("body")
        if body is not None:
            body_str = upstream_error_text(body, client)
            detail = f": {body_str}"
        else:
            detail = ""
        return scrub(
            f"HTTP {status} on the read-after GET{detail}",
            secrets,
        )
    return None


def _body_identity(read: dict[str, Any]) -> Any:
    """What a read's body is, for the no-op comparison (text body or binary bytes)."""
    return (read.get("body"), read.get("bodyBase64"))


def _is_2xx(status: Any) -> bool:
    return isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300


#: Why a relay ``noOp`` is null beside ``readAfterError`` / ``postWriteError``.
NO_OP_REASON_KEY = "noOpReason"


def _requested_leaf_paths(
    wanted: dict[str, Any], prefix: tuple[str, ...] = ()
) -> list[tuple[str, ...]]:
    """Every leaf path of a write body: a non-empty object is descended into; anything
    else (scalar, list, empty object) is one leaf compared whole."""
    paths: list[tuple[str, ...]] = []
    for name, value in wanted.items():
        path = (*prefix, name)
        if isinstance(value, dict) and value:
            paths.extend(_requested_leaf_paths(value, path))
        else:
            paths.append(path)
    return paths


def _leaf_at(record: dict[str, Any], path: tuple[str, ...]) -> Any:
    """The value at ``path`` in ``record``, or ``MISSING`` where the path is absent."""
    current: Any = record
    for name in path:
        if not isinstance(current, dict) or name not in current:
            return MISSING
        current = current[name]
    return current


def _relay_resource(read: dict[str, Any], wanted: dict[str, Any]) -> dict[str, Any] | None:
    """The object a 2xx relay read describes, for the requested-leaf comparison.

    The read body itself when it carries any top-level field the write names; else the
    single object of a ``{data: {...}}`` or ``{data: [{...}]}`` envelope (Integration and
    Classic single-resource reads); else the body object. ``None`` when the body is not a
    JSON object (text, binary) or a ``data`` list does not hold exactly one object.
    """
    body = read.get("body")
    if not isinstance(body, dict):
        return None
    body = strip_additive_keys(body)
    if any(name in body for name in wanted):
        return body
    data = body.get("data")
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        if len(data) == 1 and isinstance(data[0], dict):
            return data[0]
        return None
    return body


def _leaves_verdict(
    wanted: dict[str, Any], before: dict[str, Any] | None, after: dict[str, Any] | None
) -> tuple[bool | None, str | None]:
    """``noOp`` over the requested leaves only: ``True`` when each leaf the write names is
    identical before and after (type-strict), ``False`` when any differs or appears or
    disappears, ``None`` (with the reason) when a read cannot be matched, or when no
    leaf differs but a requested leaf is absent from both reads (unobservable).
    Unrequested siblings never count."""
    if before is None or after is None:
        return None, (
            "the read-before/read-after bodies are not single JSON objects, so the "
            "requested fields cannot be compared"
        )
    unobservable: list[str] = []
    for path in _requested_leaf_paths(wanted):
        prior, current = _leaf_at(before, path), _leaf_at(after, path)
        if prior is MISSING and current is MISSING:
            unobservable.append(".".join(path))
        elif prior is MISSING or current is MISSING or not leaf_equal(prior, current):
            return False, None
    if unobservable:
        return None, f"requested fields {unobservable!r} are absent from both reads"
    return True, None


def _no_op_verdict(
    method: str,
    status: int | None,
    read_before: dict[str, Any] | None,
    read_after: dict[str, Any] | None,
    body: Any = None,
) -> tuple[bool | None, str | None]:
    """The relay's no-op verdict and, when it is ``None``, why.

    ``True`` (nothing changed) / ``False`` (changed) only when the write was accepted
    (2xx; on a Classic route also ``meta.rc == "ok"``, so the caller passes ``status=None``
    for a Classic error) AND both reads succeeded (2xx, and ``rc == "ok"`` on a Classic
    route); any other combination (a rejected write, a failed or non-2xx read, whose
    reason is ``readAfterError``) is ``None``.

    - PUT/PATCH with an object body: only the requested leaves are compared
      (:func:`_leaves_verdict`), so a server-side change to an unrequested sibling
      (a timestamp, a counter) is never reported as a change.
    - A body-less (or non-object) write: whole-body identity of the two reads
      (type-strict: ``true`` never equals ``1``; binary compares bytes).
    - DELETE: ``False`` (deleted) only when the read-before succeeded and the
      read-after answers 404; a read-after that still returns the resource is ``None``
      ("deletion not confirmed"), never a change and never a no-op.
    """
    if not _is_2xx(status) or read_before is None or read_after is None:
        return None, None
    after = read_after.get("status")
    if method == "DELETE":
        if _read_ok(read_before) and after == 404:
            return False, None
        if _read_ok(read_before) and _read_ok(read_after):
            return None, (
                f"the resource is still readable after the DELETE (HTTP {after}): "
                "deletion not confirmed"
            )
        return None, None
    if not (_read_ok(read_before) and _read_ok(read_after)):
        return None, None
    wanted = strip_additive_keys(body) if isinstance(body, dict) else None
    if wanted:
        return _leaves_verdict(
            wanted, _relay_resource(read_before, wanted), _relay_resource(read_after, wanted)
        )
    return leaf_equal(_body_identity(read_before), _body_identity(read_after)), None


def _relay_dry_run(client: UniFiClient, url: str) -> bool:
    return (
        getattr(client, "dry_run", False) is True
        or switches.dry_run_active(path=decoded_path(url))
        or request_dry_run_active()
    )


async def _safe_get(
    client: UniFiClient,
    url: str,
    key: APIKeyConfig | None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Best-effort GET of a relay URL for read-before/after. Never raises.

    ``params`` are the write's own query parameters, so the read targets the same
    resource the write does (an Integration ordering route is selected by its query).

    Any failure — a transport error, a persistent HTTP 429 (``RateLimitError``) or anything
    else — is reported as ``{"status": None, "error": "Type: reason"}``, so a read that
    fails AFTER an applied write can never make that write look failed.
    """
    try:
        resp = await client.request("GET", url, key=key, params=params, raise_on_error=False)
        read = {
            "status": resp.status_code,
            **_relay_body(resp),
            **_redirect_headers(client, resp, key),
        }
        read.update(_classic_rc_marker(url, read["status"], read.get("body")))
        return read
    except Exception as exc:
        return {
            "status": None,
            "error": scrub(
                f"{type(exc).__name__}: {upstream_error_text(exc, client)}",
                configured_secrets(
                    getattr(client, "_settings", None),
                    include_call=bool(
                        getattr(getattr(client, "_settings", None), "redact_secrets", False)
                    ),
                ),
            ),
        }


def _device_twin(final_path: str) -> tuple[str, str] | None:
    """``(stat/device path, device _id)`` when ``final_path`` is a Classic
    ``rest/device/<_id>`` route, else ``None``."""
    match = _CLASSIC_DEVICE_WRITE_RE.match(final_path.strip("/"))
    if match is None:
        return None
    return f"{match.group(1)}/stat/device", match.group(2)


def _twin_records(read: dict[str, Any], device_id: str) -> list[Any] | None:
    """The ``stat/device`` records of the one device ``device_id`` names (its ``_id``, or
    its MAC when the path segment is one), or ``None`` when the read is not a 2xx
    ``{data: [...]}`` body."""
    body = read.get("body")
    if not _read_ok(read) or not isinstance(body, dict):
        return None
    rows = body.get("data")
    if not isinstance(rows, list):
        return None
    # Validate the whole source before narrowing the twin to one device.
    rows = object_records(rows, "Classic device read twin data")
    wanted = device_id.lower()
    return [
        row
        for row in rows
        if isinstance(row, dict)
        and (
            same_id(device_id, row.get("_id"))
            or (isinstance(row.get("mac"), str) and row["mac"].lower() == wanted)
        )
    ]


async def _safe_device_twin_get(
    client: UniFiClient,
    relay_base: str,
    twin: tuple[str, str],
    key: APIKeyConfig | None,
) -> dict[str, Any]:
    """Read the site's complete device list, preserving the upstream body verbatim.

    Selected records are reported separately in ``comparisonRecords``; ``twin`` names
    the read path and selector. A list without the device retains its complete body
    and status and adds ``twinError``. Never raises.
    """
    twin_path, device_id = twin
    read = await _safe_get(client, relay_base + twin_path, key)
    read["twin"] = {"method": "GET", "path": twin_path, "match": {"_id": device_id}}
    try:
        records = _twin_records(read, device_id)
    except UniFiConnectionError as exc:
        # Preserve the complete upstream read and mark verification unknown.
        read["twinError"] = str(exc)
        return read
    if records is not None:
        read["comparisonRecords"] = records
        if not records:
            read["twinError"] = f"no device with _id {device_id!r} in GET {twin_path}"
    return read


def _twin_record(read: dict[str, Any] | None) -> dict[str, Any] | None:
    """The ONE device record a 2xx device-twin read returned, or ``None``."""
    if read is None or not _read_ok(read) or read.get("twinError"):
        return None
    rows = read.get("comparisonRecords")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return None
    return strip_additive_keys(rows[0])


def _device_twin_verdict(
    status: int | None,
    body: Any,
    read_before: dict[str, Any] | None,
    read_after: dict[str, Any] | None,
) -> tuple[bool | None, str | None]:
    """The no-op verdict of a Classic device write read through ``stat/device``.

    ``stat/device`` carries live statistics (uptime, counters, client counts) that change
    between any two reads, so whole-record identity would call every write a change. The
    verdict compares only the leaves the body WRITES (:func:`_leaves_verdict`, nested
    objects leaf by leaf): ``True`` when each is identical before and after (type-strict),
    ``False`` when any differs, ``None`` when the write was not 2xx, there is no body, or
    a read lacks the record or every requested leaf.
    """
    if not _is_2xx(status) or not isinstance(body, dict):
        return None, None
    wanted = strip_additive_keys(body)
    if not wanted:
        return None, None
    before, after = _twin_record(read_before), _twin_record(read_after)
    if before is None or after is None:
        if read_before is None or read_after is None:
            return None, None
        return None, "a device-twin read did not return exactly one device record"
    return _leaves_verdict(wanted, before, after)


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
        scrub(path, configured_secrets(extra=request_path_secrets(method, path))),
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
    raise_on_error: bool = False,
) -> dict[str, Any]:
    """Relay a GET through the Fabric connector (no confirm).

    Known state-changing GET routes obey the connector and area write opt-outs,
    read-only mode and dry-run, and are sent once. Ordinary GET reads remain available.

    Returns the upstream status, ``contentType`` and verbatim body plus the resolved
    route class. A binary body (an image, a file) is returned complete as ``bodyBase64``
    with ``sizeBytes`` and ``body`` null (see :func:`_relay_body`). A 4xx/5xx is
    reported as ``status`` rather than raised — a GET probe of an unknown route surfaces
    its own status. Set raise_on_error to raise with the original error text before
    decoding a JSON response body.
    """
    route_class = _validate_relay_path(path, scope)
    if is_write_request("GET", path):
        try:
            guard_action("GET")
        except ReadOnlyModeError:
            _audit_refusal(client, "GET", path, switches.READ_ONLY_ENV)
            raise
        if not switches.connector_writes_enabled():
            _audit_refusal(client, "GET", path, CONNECTOR_WRITE_ENV)
            raise mark_write_denied(ValueError(connector_write_refusal("GET")))
        area_env = _opted_out_relay_env(route_class)
        if area_env is not None:
            _audit_refusal(client, "GET", path, area_env)
        _check_area_opt_out("GET", route_class)
        _check_unclassified_mutation("GET", route_class)
    _check_site_given(path.strip().strip("/"), site)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    final_path = await _substitute_site(path, site, host_id, registry, key)
    _check_final_charset(final_path)
    url = _RELAY_BASE.format(host_id=host_id) + final_path
    resp = await client.request("GET", url, key=key, params=params, raise_on_error=False)
    status = resp.status_code
    if raise_on_error and status >= 400:
        raise UniFiConnectionError(
            f"GET {final_path}: HTTP {status}: {upstream_error_text(resp.text, client)}",
            status=status,
        )
    relayed = _relay_body(resp)
    dry_run = is_write_request("GET", path) and _relay_dry_run(client, url)
    marker = {} if dry_run else _classic_rc_marker(url, status, relayed.get("body"))
    if is_write_request("GET", path):
        _audit_mutation(
            host,
            site,
            "GET",
            path,
            False,
            "dry_run" if dry_run else _marker_outcome(marker, status),
            None if dry_run else status,
        )
    _logger.debug(
        "connector-relay-get host=%s site=%s path=%s outcome=%s",
        host,
        site if site is not None else "-",
        path,
        _marker_outcome(marker, status),
    )
    return _route_response(
        client,
        "GET",
        final_path,
        {
            "method": "GET",
            "routeClass": route_class,
            "scope": scope,
            "path": path,
            "resolvedPath": final_path,
            "status": "dry_run" if dry_run else status,
            **relayed,
            **_redirect_headers(client, resp, key),
            **marker,
        },
    )


async def connector_write(
    client: UniFiClient,
    registry: Registry,
    host: str,
    method: str,
    path: str,
    *,
    site: str | None = None,
    body: RelayBody = None,
    params: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
    write_enabled: bool = True,
) -> dict[str, Any]:
    """Relay a mutating method (POST/PUT/PATCH/DELETE) through the Fabric connector.

    Capability gating: connector writes are enabled by default, so the mutation is
    refused — before any network call — only when it is explicitly opted out, i.e.
    ``write_enabled`` is False (``UNIFI_WRITE_EXCEPTIONS`` contains
    ``family:connector=deny``), or when the route class belongs to an area whose own write opt-out is set (a ``protect-*``
    route under ``family:protect=deny``; see :data:`_AREA_OPT_OUTS`). The
    write itself is never auto-retried on a 429.
    The ``confirm`` argument is accepted for backward compatibility and no longer
    required. For PUT/PATCH/DELETE the resource is read before and after the
    write with diff-based no-op detection. The upstream status/body (verbatim, a binary
    body base64-encoded as ``bodyBase64`` — see :func:`_relay_body`) and the resolved
    route class are returned; a 4xx/5xx is reported, not raised, so an
    invalid-ID probe surfaces its reachability status. ``params`` is sent as the query
    string of the write and of its read-before/read-after.
    """
    method_u = method.strip().upper()
    if method_u not in _MUTATION_METHODS:
        raise ValueError(f"connector_write does not handle {method_u!r}; use connector_get for GET")
    # Global read-only switch (UNIFI_WRITE_POLICY=deny): refuse the relayed mutation before
    # ANY upstream call — including the PUT/PATCH/DELETE read-before — so a read-only
    # server never touches the console through the generic write relay.
    # Every gate refusal is audited (outcome=refused, reason = the gate's variable).
    try:
        guard_action(method_u)
    except ReadOnlyModeError:
        _audit_refusal(client, method_u, path, switches.READ_ONLY_ENV)
        raise
    # 1) Path/namespace/scope validation and 2) gating happen with NO network calls,
    #    so a rejected mutation never touches the console or resolves a key.
    route_class = _validate_relay_path(path, scope)
    if not write_enabled:
        _audit_refusal(client, method_u, path, CONNECTOR_WRITE_ENV)
        raise mark_write_denied(ValueError(connector_write_refusal(method_u)))
    area_env = _opted_out_relay_env(route_class)
    if area_env is not None:
        _audit_refusal(client, method_u, path, area_env)
    _check_area_opt_out(method_u, route_class)
    _check_unclassified_mutation(method_u, route_class)
    # The site a path placeholder needs is checked here, before the host is resolved.
    _check_site_given(path.strip().strip("/"), site)

    require_unmasked_fields(body, f"{method_u} body")

    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    final_path = await _substitute_site(path, site, host_id, registry, key)
    _check_final_charset(final_path)
    url = _RELAY_BASE.format(host_id=host_id) + final_path

    relay_base = _RELAY_BASE.format(host_id=host_id)
    device_twin = _device_twin(final_path) if method_u in _REMAPPED_TWIN_METHODS else None

    twin_allowed = not state_changing_get_route(final_path)

    async def read_twin() -> dict[str, Any]:
        if device_twin is not None:
            return await _safe_device_twin_get(client, relay_base, device_twin, key)
        return await _safe_get(client, url, key, params)

    read_before: dict[str, Any] | None = None
    if method_u in _TWIN_METHODS and twin_allowed:
        read_before = await read_twin()

    try:
        resp = await client.request(
            method_u,
            url,
            key=key,
            json=body,
            send_json_null=_explicit_null_body.get(),
            params=params,
            raise_on_error=False,
            strip_additive=False,
            # Every relayed non-GET is a write for dry-run, read-only and the audit log,
            # even on a path the typed tools treat as a read-POST (Classic stat/*): the
            # relay's caller chooses the path.
            always_write=True,
            # Sent once (the client never retries a non-GET): a retried physical action
            # (siren, relay output, Classic cmd) repeats it. A 429 raises RateLimitError.
        )
        status: int | None = resp.status_code
    except UniFiConnectionError as exc:
        _audit_mutation(host, site, method_u, path, confirm, "error", None)
        raise UniFiConnectionError(f"Connector {method_u} relay failed: {exc}") from exc
    except RateLimitError as exc:
        _audit_mutation(host, site, method_u, path, confirm, "rate_limited", 429)
        raise RateLimitError(
            f"Connector {method_u} relay was rate limited and NOT retried (a relayed "
            f"mutation is sent once, since a retry can repeat a physical action): {exc}"
        ) from exc

    # The write has been sent: from here on nothing may lose its outcome or its audit
    # line. Any exception in the post-write processing (body decoding, redirect headers,
    # the read-after, the no-op verdict) still returns the write's status and the complete
    # raw body (base64), with the failure under ``postWriteError``.
    audited = False

    def audit(outcome: str, audit_status: int | None) -> None:
        nonlocal audited
        if not audited:
            audited = True
            _audit_mutation(host, site, method_u, path, confirm, outcome, audit_status)

    redact = getattr(getattr(client, "_settings", None), "redact_secrets", False) is True
    base: dict[str, Any] = {
        "method": method_u,
        "routeClass": route_class,
        "scope": scope,
        "path": mask_request_path(method_u, path, redact_secrets=redact),
        "resolvedPath": mask_request_path(method_u, final_path, redact_secrets=redact),
    }
    try:
        resp_body = _route_response(
            client,
            method_u,
            final_path,
            {**_relay_body(resp), **_redirect_headers(client, resp, key)},
        )

        # dry-run policy: nothing was written, so a read-after (and a no-op verdict from
        # it) would describe a write that never happened; the preview is the result.
        dry_run = _relay_dry_run(client, url)
        # A Classic write answered 2xx without meta.rc == "ok" was rejected: the body
        # stays verbatim, the marker says why, and no noOp/changed verdict is drawn.
        marker = {} if dry_run else _classic_rc_marker(url, status, resp_body.get("body"))
        if dry_run:
            # Nothing was sent: the audit line and the result say dry_run, never a status
            # the upstream did not return.
            audit("dry_run", None)
        elif marker:
            audit(_marker_outcome(marker, status), status)
        else:
            audit(_outcome(status), status)

        read_after: dict[str, Any] | None = None
        if method_u in _TWIN_METHODS and twin_allowed and not dry_run:
            read_after = await read_twin()

        no_op_reason: str | None = None
        if dry_run or marker:
            no_op = None
        elif not twin_allowed:
            no_op = None
            no_op_reason = "GET on this route changes state; no read twin is available"
        elif device_twin is not None:
            no_op, no_op_reason = _device_twin_verdict(status, body, read_before, read_after)
        else:
            no_op, no_op_reason = _no_op_verdict(method_u, status, read_before, read_after, body)

        result: dict[str, Any] = {
            **base,
            "status": "dry_run" if dry_run else status,
            **resp_body,
            "writeEnabled": write_enabled,
            **marker,
        }
        if method_u in _TWIN_METHODS and not twin_allowed:
            result["noOp"] = None
            result[NO_OP_REASON_KEY] = no_op_reason
        if method_u in _TWIN_METHODS and twin_allowed:
            result["readBefore"] = _route_response(client, "GET", final_path, read_before)
            result["readAfter"] = _route_response(client, "GET", final_path, read_after)
            result["noOp"] = no_op
            if no_op is not None:
                result["changed"] = not no_op
            # The write above already happened; say why the read-after did not return the
            # resource instead of letting its failure stand in for the write's outcome.
            read_error = _read_after_error(client, read_after, method_u)
            with_read_after_error(result, read_error)
            if no_op is None and no_op_reason is not None and read_error is None:
                result[NO_OP_REASON_KEY] = no_op_reason
            if device_twin is not None:
                # What noOp/changed compared: the body's fields in the device's record.
                result["noOpBasis"] = {
                    "readPath": device_twin[0],
                    "fields": sorted(body) if isinstance(body, dict) else [],
                }
        if not dry_run and (not _is_2xx(status) or "readAfterError" in result):
            if "bodyBase64" in result:
                result.update(_route_fallback_body(client, method_u, final_path, resp, failed=True))
            return _failed_write_result(client, method_u, final_path, result)
        return result
    except Exception as exc:
        # Under dry-run policy the client answered with its preview and sent nothing.
        previewed = _relay_dry_run(client, url)
        if previewed:
            audit("dry_run", None)
        else:
            audit(_outcome(status), status)
        # Scrub complete bound route values before field masking can split a URL
        # at a credential-shaped query parameter and leave its path token exposed.
        error_secrets = configured_secrets(
            getattr(client, "_settings", None),
            include_call=bool(getattr(getattr(client, "_settings", None), "redact_secrets", False)),
        )
        # Keep exception formatting semantics after scrubbing bound values; a plain
        # string would be parsed as a JSON body and skip embedded text masking.
        error_text = upstream_error_text(RuntimeError(scrub(str(exc), error_secrets)), client)
        fallback: dict[str, Any] = {
            **base,
            "status": "dry_run" if previewed else status,
            **_route_fallback_body(client, method_u, final_path, resp, failed=not previewed),
            "writeEnabled": write_enabled,
            # Configured server secrets are always scrubbed; bound route values follow
            # the same opt-in redaction policy as every other returned error body.
            "postWriteError": scrub(f"{type(exc).__name__}: {error_text}", error_secrets),
        }
        if method_u in _TWIN_METHODS:
            fallback["readBefore"] = _route_response(client, "GET", final_path, read_before)
            fallback["readAfter"] = None
            fallback["noOp"] = None
        return (
            fallback if previewed else _failed_write_result(client, method_u, final_path, fallback)
        )


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import connector  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the connector tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=WRITE)
    @state_changing_get
    async def fabric_connector_get(
        host: str,
        path: str,
        site: str | None = None,
        params: dict[str, Any] | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Relay a GET through the Fabric connector to any console /proxy/{path} route.

        Reaches private APIs too; official-only setups also exclude source:relay.

        For routes without typed tools. GET needs no confirm. State-changing GET routes
        (Protect enable-control/disable-control) require write authorization, obey connector/area
        opt-outs, read-only mode and dry-run, and are sent once. In discovery mode use
        call_write_tool for them. Ordinary GET reads remain available. A 4xx/5xx returns status
        (unknown-route probes).

        Consequence: Protect enable-control/disable-control changes camera controllability
        until set back.

        Under dry-run policy (UNIFI_WRITE_POLICY=dry-run) an action GET sends nothing: status
        "dry_run", body previews method, path, params, body.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body}; body is
        the upstream body verbatim: decoded JSON, the exact text of a non-JSON body, or null when
        the body is empty (masked only when the operator opts in with UNIFI_REDACT_SECRETS).
        contentType is the upstream Content-Type (null when none). A text body is decoded with its
        declared charset when that is a known codec (latin-1, utf-16 ...; UTF-8
        otherwise), so non-UTF-8 text comes back as text under body. A binary body (a non-text
        Content-Type such as image/jpeg, or bytes that do not decode in that charset) is returned
        complete, with no size cap, base64-encoded as bodyBase64 plus sizeBytes, and body is null.
        A 3xx (never followed) also returns its response headers (Location included; credentials
        and cookies excluded) under headers.

        HTTP 401/403 keeps body and status, adding _hint with key setup/permission advice.
        A 2xx error body (Classic without meta.rc "ok": _classicRcError, meta.msg included; v2 of
        only {error: {code, message}}: _upstreamError) is reported like a 4xx, body verbatim.

        Connector limits (Site Manager spec): 25 s/request, 100 requests/min/console, 10 MB response
        body, firmware 5.0.3+; a matching 408/429/502 adds a hint.

        Required arguments: host, path.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite).
            path: the relay-relative application path AFTER ``/proxy/`` — e.g.
                ``network/integration/v1/sites`` or ``network/api/s/{site}/stat/device``. Use the
                ``{site}`` (slug) or ``{site_id}`` (UUID) placeholder for the site segment; the server
                resolves and substitutes it, and resolvedPath reports the path as sent (the console id
                and API key are never part of path or resolvedPath). Mapped application routes carry
                their routeClass; unmapped routes relay as
                routeClass "unclassified". Ordinary GET reads relay while an area write opt-out
                is active. Mutations on unclassified routes are refused only while an area write
                opt-out is active, with the refusal naming its variable. ``..``, ``%``-encoding,
                and control characters are rejected.
            site: site name or UUID — REQUIRED only when path contains a site placeholder.
            params: optional query-string parameters.
                Free-form JSON object; the caller-chosen route determines its shape.
            scope: optional 'device' / 'site' / 'global' — cross-checked against the path so a device
                route cannot be confused with a site-global setting route.
        """
        client, registry = deps_fn()
        return await connector.connector_get(
            client, registry, host, path, site=site, params=params, scope=scope
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_post(
        host: str,
        path: str,
        site: str | None = None,
        body: connector.RelayBody = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a POST (create/command) through the Fabric connector. Writes to the controller.

        Reaches private APIs too.

        Consequence: whatever the target route creates or does happens on the live controller
        immediately.

        POST targets a collection or command route (e.g. ``network/api/s/{site}/cmd/...``). See
        fabric_connector_get for host/path/site/scope semantics; body is sent verbatim and confirm is
        ignored. Every attempt is audit-logged (never the key value).

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
        writeEnabled}. status and body are the upstream's, verbatim (a 4xx/5xx is returned, not raised);
        a binary body is bodyBase64 plus sizeBytes with body null; a 3xx (never followed) adds its
        headers. POST has no GET twin: no read-before/after. Under dry-run policy (UNIFI_WRITE_POLICY=dry-run) nothing is sent:
        status
        is "dry_run" and body is the preview.

        Refused before any request if family:connector=deny, UNIFI_WRITE_POLICY=deny is set, a
        protect/ path meets family:protect=deny (every area write opt-out applies),
        or an unclassified route meets any active area opt-out; never auto-retried on 429
        (raised with the upstream body).

        Full request shapes are in the parameter schema; detailed examples and workflows:
        docs/TOOL-USAGE.md#fabric_connector_post.

        HTTP 401/403 keeps body and status, adding _hint with key setup/permission advice.
        A 2xx error body (Classic without meta.rc "ok": _classicRcError, meta.msg included; v2 of
        only {error: {code, message}}: _upstreamError) is reported like a 4xx, body verbatim.

        Connector limits (Site Manager spec): 25 s/request, 100 requests/min/console, 10 MB response
        body, firmware 5.0.3+; a matching 408/429/502 adds a hint.

        Required arguments: host, path.

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
                Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
                The caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "POST",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_put(
        host: str,
        path: str,
        site: str | None = None,
        body: connector.RelayBody = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a PUT (full replace) through the Fabric connector. Writes upstream.

        Reaches private APIs too.

        Consequence: replaces the resource now; omitted fields may reset.

        For ``network/api/s/{site}/rest/device/{id}``, pass scope='device' to refuse site-global
        routes; it has no GET, so reads use stat/device and noOp compares only sent fields
        (noOpBasis). A device write can restart or reprovision it. Undocumented routes are
        EXPERIMENTAL. fabric_connector_get defines host/path/site/scope; body is verbatim; confirm
        is ignored.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
        writeEnabled, readBefore, readAfter, noOp[, changed, noOpBasis]}. status/body are verbatim
        (4xx/5xx too); binary is {bodyBase64, sizeBytes, body: null}; an unfollowed 3xx adds
        headers. readBefore/readAfter are twin GET results ({status: null, error} on failure);
        readAfterError explains a failed or non-2xx read-after. For rest/device each read has the
        stat/device list as body, matched comparisonRecords, twin and twinError (why a device
        was not compared). noOp is true only if the write and both reads are 2xx and every sent
        leaf matches (unsent siblings ignored; body-less writes compare whole bodies);
        null if unknown (noOpReason unless readAfterError explains). changed (= not noOp) is
        present only when noOp is non-null. A 2xx error body (Classic: _classicRcError with
        meta.msg; v2: _upstreamError) is rejected: noOp is null, reads carry the marker.
        dry-run policy (UNIFI_WRITE_POLICY=dry-run) sends nothing: status "dry_run", body the
        preview (method, path, params, body); readAfter/noOp null.

        Refused before requests if family:connector=deny, UNIFI_WRITE_POLICY=deny is set,
        a protect/ path has family:protect=deny, or
        an unclassified route meets an active area opt-out; never auto-retried on 429
        (raised with its body).

        Details: docs/TOOL-USAGE.md#fabric_connector_put; limits: see fabric_connector_get.

        HTTP 401/403 adds _hint (key/permission advice);
        readBefore/readAfter carry the same guidance for failed GET twins.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
                Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
                The caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "PUT",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_patch(
        host: str,
        path: str,
        site: str | None = None,
        body: connector.RelayBody = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a PATCH (partial update) through the Fabric connector. Writes upstream.

        Reaches private APIs too.

        Consequence: applies to the live controller immediately.

        Classic rest/device/{id} reads use stat/device as for fabric_connector_put; a device write
        can restart or reprovision it. For legacy
        InnerSpace ``innerspace/api/shapes/{id}``, first
        probe a nonexistent shape ID with an empty body: 4xx = reachable; 200/204 = stop.
        EXPERIMENTAL. fabric_connector_get defines host/path/site/scope; body is verbatim; confirm is
        ignored.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
        writeEnabled, readBefore, readAfter, noOp[, changed]}. status/body are verbatim
        (4xx/5xx too); binary is {bodyBase64, sizeBytes, body: null}; an unfollowed 3xx adds
        headers. readBefore/readAfter are twin GET results ({status: null, error} on failure);
        readAfterError explains a failed or non-2xx read-after. For rest/device each read has the
        stat/device list as body, matched comparisonRecords, twin and twinError (why a device
        was not compared). noOp is true only if the write and both reads are 2xx and every sent
        leaf matches (unsent siblings ignored; body-less writes compare whole bodies);
        null if unknown (noOpReason unless readAfterError explains). changed (= not noOp) is
        present only when noOp is non-null. A 2xx error body (Classic: _classicRcError with
        meta.msg; v2: _upstreamError) is rejected: noOp is null, reads carry the marker.
        dry-run policy (UNIFI_WRITE_POLICY=dry-run) sends nothing: status "dry_run", body the
        preview (method, path, params, body); readAfter/noOp null.

        Refused before requests if family:connector=deny, UNIFI_WRITE_POLICY=deny is set,
        a protect/ path has family:protect=deny, or
        an unclassified route meets an active area opt-out; never auto-retried on 429
        (raised with its body).

        Details: docs/TOOL-USAGE.md#fabric_connector_patch; limits: see fabric_connector_get.

        HTTP 401/403 adds _hint (key/permission advice);
        readBefore/readAfter carry the same guidance for failed GET twins.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
                Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
                The caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "PATCH",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_delete(
        host: str,
        path: str,
        site: str | None = None,
        body: dict[str, Any] | None = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a DELETE through the Fabric connector. Irreversible write to the controller.

        Reaches private APIs too.

        Consequence: the target resource is removed from the controller; there is no undo.

        DELETE reads its GET twin before/after; confirm the exact resource path first; body is
        optional. fabric_connector_get defines host/path/site/scope; body is verbatim; confirm is
        ignored.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
        writeEnabled, readBefore, readAfter, noOp[, changed]}. status/body are verbatim
        (4xx/5xx too); binary is {bodyBase64, sizeBytes, body: null}; an unfollowed 3xx adds
        headers. readBefore/readAfter are twin GET results ({status: null, error} on failure);
        readAfterError explains a failed or non-2xx read-after. DELETE is confirmed only by a
        404 read-after following a 2xx read-before: noOp false, changed true. If read-after still
        returns the resource, noOp is null with noOpReason "deletion not confirmed". Unknown is also
        noOp null; changed (= not noOp) is present only when noOp is non-null.
        A 2xx error body is rejected: status/body stay verbatim; Classic without meta.rc "ok" sets
        _classicRcError (meta.msg included), a v2 body of only {error: {code, message}} sets
        _upstreamError; noOp is null with no changed, and reads carry the marker.
        dry-run policy (UNIFI_WRITE_POLICY=dry-run) sends nothing: status "dry_run", body the
        {method, path, params, body} preview, readAfter/noOp null, no changed.

        Refused before requests if family:connector=deny, UNIFI_WRITE_POLICY=deny is set,
        a protect/ path has family:protect=deny, or
        an unclassified route meets any active area opt-out; never auto-retried on 429
        (raised with its body).

        Details: docs/TOOL-USAGE.md#fabric_connector_delete.

        Connector limits (Site Manager spec): 25 s/request, 100 requests/min/console, 10 MB response
        body, firmware 5.0.3+; a matching 408/429/502 adds a hint.

        HTTP 401/403 keeps body/status and adds _hint (key/permission advice);
        readBefore/readAfter carry the same guidance for failed GET twins.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Optional for DELETE.
                Omit to send no body; an explicit null is sent as the JSON body null.
                Free-form JSON object; the caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "DELETE",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    return {
        "fabric_connector_get": fabric_connector_get,
        "fabric_connector_post": fabric_connector_post,
        "fabric_connector_put": fabric_connector_put,
        "fabric_connector_patch": fabric_connector_patch,
        "fabric_connector_delete": fabric_connector_delete,
    }
