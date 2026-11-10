"""The server's one empty-update guard.

An update whose body carries no field to change must fail before any request, including
host/site resolution reads. All locally decidable checks run before upstream-dependent
selector resolution. Sending ``PATCH {}`` / ``PUT {}``
would report a write that changed nothing, or a read-before would answer "no change
needed" for a call that asked for nothing.

The *effective* body is what the client would really send, judged field by field:

* top-level additive ``_`` keys a read adds (``_keyLabel``, ``_resolved_networks``,
  ...; ``_id`` is a real Classic field and is kept) are never sent
  (``client.strip_additive_keys``);
* a field holding exactly the redaction mask is never sent
  (``redaction.drop_masked_fields``), so the upstream keeps its stored secret;
* an empty nested object carries no field (``{"osdSettings": {}}`` changes nothing in a
  partial update);
* a key that only addresses the object (``_id``, ``id``, ``site_id``; ``key`` for
  ``update_setting``: :data:`IDENTITY_FIELDS`) carries no field to change: an
  identity-only body (``{"_id": ...}``) is empty for Classic and every other update
  tool, though the key is still sent next to a real field;
* a server-managed top-level field an Integration update never sends (``id``,
  ``metadata``, ``default``, ``index`` but where the request schema accepts it, as on ACL
  rules; ``tools._payload.INTEGRATION_UPDATE_KEEP``) carries no field, so the guard judges
  the FINAL sanitized body, not the one the caller passed.

When nothing is left the call raises ``ValueError("No fields provided: ...")``, worded by
the tool's kind (:func:`body_kind`): an update asks for a field to change; a create or an
action names the keys its published request schema requires
(:data:`CREATE_ACTION_REQUIRED_KEYS`) or points at its description. Every
write tool whose payload is ONE required object body reaches this check -- updates,
full-replace writes such as ``set_*_ordering``, creates and actions alike (the
selection is "a write tool taking a single required object body", derived from the
registry, never a name prefix) -- through :class:`EmptyUpdateMiddleware`, so a new such
tool is covered on registration. A full-replace write whose published request schema
requires a key (``orderedAclRuleIds`` / ``orderedFirewallPolicyIds``,
:data:`REQUIRED_BODY_KEYS`) also refuses a body without it before any request. The
Protect settings updates and the scalar-argument
Carrier Fabric / Mobility updates by calling :func:`require_update_fields` on the body
they build, and the HTTP client itself refuses a write whose body was non-empty but held
only masked values.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .argument_values import require_finite
from .redaction import REDACTION_MASK, drop_masked_fields, note_dropped_fields

#: The fixed opening of every empty-update error.
NO_FIELDS = "No fields provided"

#: Top-level body keys that only ADDRESS the object an update tool writes (the object is
#: named by the tool's id argument and its URL), never a field to change: a body of only
#: these (``{"_id": ...}``, ``{"id": ...}``) is empty. They are still sent alongside a
#: real field (a Classic PUT of a read result carries its ``_id``).
IDENTITY_FIELDS = frozenset({"_id", "id", "site_id"})

#: Further identity keys of specific update tools (``update_setting`` addresses the setting
#: group by its ``key``, which its ``setting_key`` argument already names).
TOOL_IDENTITY_FIELDS: dict[str, frozenset[str]] = {
    "update_setting": frozenset({"key"}),
    # The Classic networkconf writes pin ``purpose`` (the record kind the tool addresses):
    # a body of only ``purpose`` changes nothing.
    "update_vpn_server": frozenset({"purpose"}),
    "update_wan_interface": frozenset({"purpose"}),
    "update_site_to_site_tunnel": frozenset({"purpose"}),
    "update_vpn_client": frozenset({"purpose"}),
}

#: Identity keys that select the record KIND a tool pins rather than the record its id
#: argument names (``purpose`` on the Classic networkconf writes). The refusal of a body of
#: only these says so instead of pointing at the id argument.
PINNED_KIND_FIELDS = frozenset({"purpose"})

#: Top-level keys the published request schema REQUIRES on a full-replace write: a body
#: without one is refused before any request (the controller would reject it, and the
#: order of every rule would be undefined). Pinned to the vendored specs by a test.
REQUIRED_BODY_KEYS: dict[str, tuple[str, ...]] = {
    "set_acl_rule_ordering": ("orderedAclRuleIds",),
    "set_firewall_policy_ordering": ("orderedFirewallPolicyIds",),
}


# Unpublished schemas do not establish an empty set of required fields.
CREATE_ACTION_BODY_PROVENANCE: dict[str, dict[str, str]] = {
    "create_firewall_rule": {
        "argument": "rule",
        "operation": "POST /ea/sites/{site_id}/rest/firewallrule",
        "schema": "unpublished",
        "empty_body_disposition": "upstream_judged",
    },
}


#: The keys the published request schema REQUIRES of the one object body of a create or
#: action tool (for ``bulk_delete_hotspot_vouchers``: its required ``filter`` query
#: parameter), named by the empty-body refusal so the caller learns what to send. Pinned to
#: the vendored specs by ``tests/test_empty_body_wording.py``. A create / action tool not
#: listed has no published request schema; its description lists the fields it takes.
CREATE_ACTION_REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "adopt_device": ("ignoreDeviceLimit", "macAddress"),
    "bulk_delete_hotspot_vouchers": ("filter",),
    "create_acl_rule": ("action", "enabled", "name", "type"),
    "create_arm_profile": (
        "activationDelay",
        "automations",
        "name",
        "recordEverything",
        "schedules",
    ),
    "create_dns_policy": ("enabled", "type"),
    "create_firewall_policy": (
        "action",
        "destination",
        "enabled",
        "ipProtocolScope",
        "loggingEnabled",
        "name",
        "source",
    ),
    "create_firewall_zone_proxy": ("name", "networkIds"),
    "create_hotspot_vouchers": ("name", "timeLimitMinutes"),
    "create_network": ("enabled", "management", "name", "vlanId"),
    "create_traffic_matching_list": ("name", "type"),
    "create_wifi_broadcast": (
        "channel2gLockedTo6",
        "clientIsolationEnabled",
        "dtimPeriod2gLockedTo3",
        "enabled",
        "hideName",
        "multicastToUnicastConversionEnabled",
        "name",
        "securityConfiguration",
        "type",
        "uapsdEnabled",
    ),
    "execute_client_action": ("action",),
    "execute_device_action": ("action",),
    "execute_port_action": ("action",),
    "pos_ingest_transaction": ("amount", "externalId", "type"),
}


def body_kind(tool: str) -> str:
    """``update`` (changes an existing object: ``update_*``, ``patch_*``, ``set_*``),
    ``create`` (``create_*``, and the POS transaction ingest) or ``action``."""
    if tool.startswith(("update_", "patch_", "set_")):
        return "update"
    if tool.startswith("create_") or tool == "pos_ingest_transaction":
        return "create"
    return "action"


def empty_body_reason(tool: str, arg: str) -> str:
    """The empty-body refusal of a create or action tool: what the body must carry."""
    gist = "nothing to create" if body_kind(tool) == "create" else "no action to send"
    required = CREATE_ACTION_REQUIRED_KEYS.get(tool)
    if required:
        need = f"The published request schema requires: {', '.join(required)}."
    else:
        need = "Pass the fields the tool description lists."
    return (
        f"{NO_FIELDS}: {tool} {arg!r} carries no field (additive '_' keys and empty objects "
        f"carry none), so there is {gist}. {need} No request was sent."
    )


def identity_fields(tool: str) -> frozenset[str]:
    """The keys ``tool`` uses only to address the object it updates."""
    return IDENTITY_FIELDS | TOOL_IDENTITY_FIELDS.get(tool, frozenset())


def strip_additive_top_level(body: Any) -> Any:
    """``body`` without the additive top-level ``_`` keys (``_id`` kept); never mutated."""
    if not isinstance(body, dict):
        return body
    return {k: v for k, v in body.items() if not str(k).startswith("_") or k == "_id"}


def has_field(node: Any, *, opaque: frozenset[str] = frozenset()) -> bool:
    """True when ``node`` carries at least one value to send.

    Anything that is not an object is a value (an empty list or string included). An
    object carries a field when any of its values does, so an object of only empty
    objects carries none. A key named in ``opaque`` is a value even when it holds an
    empty object (Carrier ``metadata``: ``{}`` replaces the document).
    """
    if isinstance(node, dict):
        return any(k in opaque or has_field(v) for k, v in node.items())
    return True


def update_problem(
    body: Any,
    what: str,
    *,
    opaque: frozenset[str] = frozenset(),
    server_managed: frozenset[str] = frozenset(),
    identity: frozenset[str] = frozenset(),
) -> tuple[Any, list[str], str | None]:
    """``(effective body, masked paths dropped, error or None)`` for an update body.

    ``server_managed`` names top-level fields the tool never sends (its sanitizer strips
    them), so they are judged as absent. ``identity`` names top-level keys that only
    address the object (:data:`IDENTITY_FIELDS`): they are kept in the effective body but
    never count as a field to change.
    """
    # JSON validity must precede every recursive sanitizer, even for direct callers.
    require_finite(body, what)
    stripped = strip_additive_top_level(body if body is not None else {})
    managed: list[str] = []
    if isinstance(stripped, dict) and server_managed:
        managed = sorted(k for k in stripped if k in server_managed)
        stripped = {k: v for k, v in stripped.items() if k not in server_managed}
    clean, dropped = drop_masked_fields(stripped)
    addressing: list[str] = []
    judged = clean
    if isinstance(clean, dict) and identity:
        addressing = sorted(k for k in clean if k in identity)
        judged = {k: v for k, v in clean.items() if k not in identity}
    if has_field(judged, opaque=opaque):
        return clean, dropped, None
    if addressing and not dropped:
        named = [k for k in addressing if k not in PINNED_KIND_FIELDS]
        pinned = [k for k in addressing if k in PINNED_KIND_FIELDS]
        parts = []
        if named:
            parts.append(f"{', '.join(named)}, which the tool's id argument already names")
        if pinned:
            parts.append(f"{', '.join(pinned)}, the record kind the tool pins")
        reason = (
            f"{NO_FIELDS}: the {what} carries only the key(s) that address the object "
            f"({'; '.join(parts)}), so the request would carry no field to change. Pass at "
            "least one field to change. No request was sent."
        )
    elif managed:
        reason = (
            f"{NO_FIELDS}: every provided {what} field is server-managed "
            f"({', '.join(managed)}) and is never sent, so the request would carry no field "
            "to change. Pass at least one settable field; read the current object with the "
            "matching get_/list_ tool to see them. No request was sent."
        )
    elif dropped:
        reason = (
            f"{NO_FIELDS}: every provided {what} field held the redaction mask "
            f"{REDACTION_MASK!r} ({', '.join(dropped)}) and is never sent, so the stored "
            "value is kept. Pass the real value for a field you want to change, or leave "
            "the field out. No request was sent."
        )
    else:
        reason = (
            f"{NO_FIELDS}: pass at least one {what} field to change (additive '_' keys and "
            "empty objects carry no field). Read the current object with the matching get_/"
            "list_ tool to see the settable fields. No request was sent."
        )
    return clean, dropped, reason


def require_update_fields(
    body: Any,
    what: str,
    *,
    opaque: frozenset[str] = frozenset(),
    server_managed: frozenset[str] = frozenset(),
    identity: frozenset[str] = IDENTITY_FIELDS,
) -> dict[str, Any]:
    """The effective update body (``_`` keys and masked fields dropped), or raise.

    Raises ``ValueError`` starting with :data:`NO_FIELDS` when the body carries no field
    to change (identity-only bodies included). Makes no request; call it before any
    resolution or read-before.
    """
    clean, _dropped, reason = update_problem(
        body, what, opaque=opaque, server_managed=server_managed, identity=identity
    )
    if _dropped:
        note_dropped_fields(_dropped)
    if reason is not None:
        raise ValueError(reason)
    return clean if isinstance(clean, dict) else {}


def require_unmasked_fields(body: Any, what: str) -> None:
    """Refuse a body whose masked fields leave nothing to send, before any request.

    Mirrors the HTTP chokepoint for optional relay bodies: an omitted or empty body
    stays valid; only a body emptied by dropping redaction masks is refused. Callers
    must run this check before resolution or read-before, even if the write is a no-op.
    """
    _clean, dropped, reason = update_problem(body, what)
    if dropped and reason is not None:
        raise ValueError(reason)


def _is_object_schema(schema: Any, root: Any = None, seen: frozenset[str] = frozenset()) -> bool:
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == "object":
        return True
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/") and ref not in seen:
        target = root
        for part in ref[2:].split("/"):
            target = (
                target.get(part.replace("~1", "/").replace("~0", "~"))
                if isinstance(target, dict)
                else None
            )
        if _is_object_schema(target, root, seen | {ref}):
            return True
    return any(_is_object_schema(s, root, seen) for s in schema.get("anyOf", ()) or ())


def _is_write_tool(tool: Any) -> bool:
    annotations = getattr(tool, "annotations", None)
    if annotations is None:
        return True
    hint = getattr(annotations, "read_only_hint", None)
    return not hint


#: Object-valued query arguments are not request bodies. The voucher filter is
#: required; relay query dictionaries are optional today. Keeping the explicit map
#: separate from body inference prevents a query from reaching empty-body handling
#: (and its host lookup) if a query argument becomes required later.
QUERY_OBJECT_ARGUMENTS: dict[str, frozenset[str]] = {
    "bulk_delete_hotspot_vouchers": frozenset({"filter_params"}),
    "fabric_connector_get": frozenset({"params"}),
    "fabric_connector_post": frozenset({"params"}),
    "fabric_connector_put": frozenset({"params"}),
    "fabric_connector_patch": frozenset({"params"}),
    "fabric_connector_delete": frozenset({"params"}),
}


def body_argument(tool: Any) -> str | None:
    """The free-form body argument of a write tool, or None.

    A WRITE tool (no ``readOnlyHint``) whose payload is one REQUIRED object-typed
    argument (``settings``, ``fields``, ``payload``, ``policy``, ``ordering``, ...),
    whatever its name: updates, full-replace writes, creates and actions. Tools whose
    fields are scalar arguments build their body themselves and call
    :func:`require_update_fields` on it. Query dictionaries listed in
    :data:`QUERY_OBJECT_ARGUMENTS` are excluded: their required-query validation
    belongs to the tool and must run before any resolution lookup.
    """
    if not _is_write_tool(tool):
        return None
    params = getattr(tool, "parameters", None) or {}
    props = params.get("properties") or {}
    required = set(params.get("required") or ())
    query_args = QUERY_OBJECT_ARGUMENTS.get(str(getattr(tool, "name", "")), frozenset())
    objects = [
        p
        for p, s in props.items()
        if _is_object_schema(s, params) and p in required and p not in query_args
    ]
    return objects[0] if len(objects) == 1 else None


#: The former name (the guard once covered ``update_*`` / ``patch_*`` names only).
update_body_argument = body_argument


def missing_required_keys(tool: str, body: Any) -> list[str]:
    """The :data:`REQUIRED_BODY_KEYS` of ``tool`` that ``body`` lacks."""
    if not isinstance(body, dict):
        return []
    return [k for k in REQUIRED_BODY_KEYS.get(tool, ()) if k not in body]


def _area_opted_out(name: str) -> bool:
    """True when the tool's area write opt-out is set (the tool then refuses first)."""
    from . import families, switches

    family = families.build_family_index().get(name)
    return any(s.governs(family) and not s.enabled() for s in switches.AREA_WRITE_SWITCHES)


class EmptyUpdateMiddleware(Middleware):
    """Refuse a write whose body carries no field (or lacks a spec-required key), before
    the tool body runs.

    Covers every registered write tool with a single required object body
    (:func:`body_argument`). Invalid bodies add no resolution or read-before. An area whose
    write opt-out is set is left to the tool,
    whose opt-out refusal comes first. A refusal is audited (``outcome=refused``,
    ``reason`` ``empty_update`` or ``required_body_fields``) through ``audit`` when given.
    """

    def __init__(
        self,
        server: Any,
        audit: Callable[[str, str], None] | None = None,
    ) -> None:
        self._server = server
        self._audit = audit
        self._body_args: dict[str, str | None] = {}
        self._required: dict[str, frozenset[str]] = {}

    async def _body_arg(self, name: str) -> str | None:
        if name not in self._body_args:
            try:
                tool = await self._server.get_tool(name)
            except NotFoundError:  # unknown tool: the framework reports it
                return None
            if tool is None:
                return None
            self._body_args[name] = body_argument(tool)
            params = getattr(tool, "parameters", None) or {}
            self._required[name] = frozenset(params.get("required") or ())
        return self._body_args[name]

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        name = str(getattr(context.message, "name", ""))
        arg = await self._body_arg(name)
        arguments = getattr(context.message, "arguments", None) or {}
        # A missing required argument is the framework's argument error, reported first.
        complete = self._required.get(name, frozenset()) <= set(arguments)
        if arg is not None and complete and not _area_opted_out(name):
            if "host" in self._required.get(name, ()) and not isinstance(
                arguments.get("host"), str
            ):
                # Let framework type validation report the host before a body error.
                return await call_next(context)
            body = arguments.get(arg)
            # A missing or mistyped body is the framework's argument error, reported next.
            if isinstance(body, dict):
                from .shared_shapes._payload import server_managed_fields

                try:
                    _clean, _dropped, reason = update_problem(
                        body,
                        f"{name} {arg!r}",
                        server_managed=server_managed_fields(name),
                        identity=identity_fields(name),
                    )
                except ValueError as exc:
                    raise ToolError(str(exc)) from None
                provenance = CREATE_ACTION_BODY_PROVENANCE.get(name, {})
                if (
                    reason is not None
                    and body == {}
                    and body_kind(name) == "create"
                    and provenance.get("argument") == arg
                    and provenance.get("schema") == "unpublished"
                    and provenance.get("empty_body_disposition") == "upstream_judged"
                ):
                    reason = None
                if reason is not None and body_kind(name) != "update" and not _dropped:
                    # A create / action body is not "a field to change": say what it needs.
                    reason = empty_body_reason(name, arg)
                if reason is not None:
                    if self._audit is not None:
                        self._audit(name, "empty_update")
                    raise ToolError(reason)
                missing = missing_required_keys(name, body)
                if missing:
                    if self._audit is not None:
                        self._audit(name, "required_body_fields")
                    raise ToolError(
                        f"Missing required field(s) {', '.join(missing)} in {name} {arg!r}: "
                        "the published request schema requires them on this full-replace "
                        f"write (e.g. {{{missing[0]!r}: [...]}}). No request was sent."
                    )
        return await call_next(context)
