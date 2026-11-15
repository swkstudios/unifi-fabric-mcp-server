"""The connector relay's write policy, shared by the relay and the server's gates.

Moved verbatim out of the connector family (public #41, design review C1) so that core code (the
server, the read-only and area opt-out gates, discovery and the read-only chokepoint)
never imports a family: the relay's route classes and pre-network path validation, the
per-area write opt-outs it honours (``switches.AREA_WRITE_SWITCHES``) with their refusal
texts, the ``family:connector=deny`` write exception, and the middleware that records an
explicit JSON-null relay body. ``unifi_fabric.families.connector.connector`` re-exports
every name, so its callers are unchanged.

The per-area refusal reasons are built from ``switches`` exactly as each area's family
module builds its own (``switches.area_deny_text(<area>, <env>)``), so the texts are equal
without importing those families.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from . import switches
from .audit_vocabulary import mask_path
from .client import UniFiClient
from .read_only import is_write_request, mark_write_denied
from .route_secrets import request_path_secrets
from .secret_scrub import configured_secrets, scrub

__all__ = [
    "_explicit_null_body",
    "RelayBodyPresenceMiddleware",
    "_ALLOWLIST",
    "_RAW_PATH_RE",
    "_FINAL_PATH_RE",
    "_DEVICE_ROUTES",
    "_GLOBAL_SETTING_ROUTES",
    "_route_segments",
    "_route_is",
    "_MUTATION_METHODS",
    "UNCLASSIFIED",
    "_area_opt_out_text",
    "_AREA_REASONS",
    "_AREA_OPT_OUTS",
    "CONNECTOR_WRITE_ENV",
    "connector_write_refusal",
    "area_write_refusal",
    "area_write_env",
    "_opted_out_relay_env",
    "relay_get_opt_out_env",
    "_active_area_opt_outs",
    "_audit_refusal",
    "_check_area_opt_out",
    "_check_unclassified_mutation",
    "unclassified_dry_run",
    "_check_raw_charset",
    "_match_namespace",
    "_check_scope",
    "_check_site_given",
    "_ALLOWED_PLACEHOLDERS",
    "_PLACEHOLDER_RE",
    "_check_placeholders",
    "_validate_relay_path",
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
    switches.PROTECT_WRITES.env: switches.area_deny_text("Protect", switches.PROTECT_WRITES.env),
    switches.MOBILITY_WRITES.env: switches.area_deny_text("Mobility", switches.MOBILITY_WRITES.env),
    switches.CARRIER_WRITES.env: switches.area_deny_text(
        "Carrier Fabric", switches.CARRIER_WRITES.env
    ),
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
            path=mask_path(
                scrub(path, configured_secrets(extra=request_path_secrets(method, path))),
                relay=True,
            ),
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


def unclassified_dry_run(method: str, route_class: str) -> bool:
    """True when a relayed mutation on an ``unclassified`` route is previewed instead of
    sent: some per-area ``family:<area>=dry-run`` entry is set.

    The dry-run twin of :func:`_check_unclassified_mutation`: the route's area cannot be
    shown to be outside the area the entry names, so the entry previews exactly the
    write its ``deny`` form refuses. Makes no network call.
    """
    if route_class != UNCLASSIFIED or method.strip().upper() == "GET":
        return False
    from . import policy

    current = policy.current()
    return any(
        policy.family_exception(current, switch.family) == "dry-run"
        for switch in switches.AREA_WRITE_SWITCHES
    )


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
