"""Opt-in credential redaction (public issue https://github.com/swkstudios/unifi-fabric-mcp-server/issues/26).

By default the server is a faithful pass-through: upstream responses are returned
verbatim and redaction is a no-op. When the operator sets ``UNIFI_REDACT_SECRETS``
to a truthy value, EVERY tool response has a DOCUMENTED, EXPLICIT set of credential
fields masked at one shared point before it leaves the server.

A key is a credential field when it matches one of three documented rules, all
case-insensitive and anchored (never a free substring search):

1. its exact name is in :data:`CREDENTIAL_FIELDS` (any value is masked, except null or
   the empty string, which hold nothing to mask), or in :data:`CREDENTIAL_STRING_FIELDS`
   and its value is a non-empty string;
2. it ends with a suffix in :data:`CREDENTIAL_SUFFIXES` (``google_maps_api_key``,
   ``wireguard_private_key``, ``utm_token``) and its value is a string;
3. it is a controller hidden ``x_`` field (not an ``x_has_`` presence flag) whose name
   ends with an ending in :data:`X_FIELD_CREDENTIAL_ENDINGS` (``x_authkey``,
   ``x_stripe_api_key``, ``x_ssh_sha512passwd``) and its value is a string.

A pagination cursor (:data:`CURSOR_FIELDS`: ``nextToken``, ``page_token`` ...) is
never a credential field, under any rule.

Rules 2 and 3 never mask a boolean, number, null, object or list (a flag such as
``radius_macacl_empty_password: false`` is a setting, not a credential); containers are
recursed into instead. Every non-credential field is left byte-identical to the
unmasked response.

Coverage is installed once, server-wide, by :func:`install_response_redaction`,
which wraps every registered tool's handler. The wrapper reads the flag at call
time: when redaction is disabled it returns the handler result unchanged (a
byte-identical pass-through with no transform), so the default output and the
pre-publish pass-through guard baseline are unaffected.

The reverse direction is handled in the client's single write path: a write body
field whose value is exactly :data:`REDACTION_MASK` is left out of the request only
when redaction is enabled (so a
redacted read fed back into an update never overwrites the stored secret with the
mask) and the dropped paths are reported on the tool result under
:data:`MASKED_FIELDS_KEY`. This is not a refusal; the rest of the write is sent.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .switches import env_flag

#: Replacement value substituted for a matched credential field.
REDACTION_MASK = "***REDACTED***"

#: Opt-in rule 1: documented explicit set of credential-class field names masked when
#: ``UNIFI_REDACT_SECRETS`` is enabled, whatever the value type. Matched
#: case-insensitively against the exact key name. Keep this list, the suffix and ``x_``
#: rules below and the docs/CONFIGURATION.md "Credential redaction" section in sync.
CREDENTIAL_FIELDS: frozenset[str] = frozenset(
    {
        # WLAN / wlanconf pre-shared keys and passwords
        "x_passphrase",
        "x_password",
        "x_iapp_key",
        "x_wep",
        "wpa_psk",
        "sae_psk",  # WPA3 SAE passwords (scalar or list), not an enable flag.
        "x_mesh_psk",
        # WPA-Enterprise / certificate key material
        "x_ca_crt",
        "x_ca_key",
        "x_certificate_crt",
        "x_certificate_key",
        "server_certificate_key",
        "x_private_key",
        "private_key",
        "privatekey",
        # RADIUS shared secrets
        "x_secret",
        "x_radius_secret",
        "radius_secret",
        # SSH / device management credentials (get_system_info, device settings)
        "x_ssh_password",
        "ssh_password",
        "x_ssh_sudopassword",
        "syslog_key",
        # VPN pre-shared keys / tunnel secrets (IPsec / L2TP / WireGuard)
        "x_ipsec_pre_shared_key",
        "ipsec_pre_shared_key",
        "pre_shared_key",
        "preshared_key",
        "presharedkey",
        "psk",
        "x_psk",
        # VPN client credentials (Classic networkconf vpn-client records: list_vpn_clients,
        # create_vpn_client / update_vpn_client bodies and dry-run previews)
        "x_wireguard_private_key",
        "x_openvpn_password",
        "openvpn_configuration",
        # API tokens / auth material / cloud access
        "api_token",
        "x_api_token",
        "api_key",
        "apikey",
        "device_auth",  # Cloud device authentication material, distinct from device_id.
        "auth_token",
        "x_auth_token",
        "access_token",
        "refresh_token",
        # Controller camelCase credential fields.
        "sharedsecret",
        "authserversecret",
        "wanpassword",
        "wireguardprivatekey",
        "clientsecret",
        "bearertoken",
        "apitoken",
        "accesstoken",
        "refreshtoken",
        "radiussecret",
        "pppoepassword",
        "sshpassword",
        # Controller x_ aliases for the documented camelCase fields.
        "x_shared_secret",
        "x_auth_server_secret",
        "x_wan_password",
        "x_client_secret",
        "x_bearer_token",
        "x_access_token",
        "x_refresh_token",
        "x_pppoe_password",
        # Generic named credential fields (WLAN, Dynamic DNS, hotspot operator,
        # RADIUS account, settings objects)
        "passphrase",
        "password",
        "secret",
        "token",
    }
)


#: Opt-in rule 1, string values only: exact credential names (matched
#: case-insensitively) whose value is masked when it is a non-empty string. A boolean,
#: number, null, object or list under one of these names is left as is.
CREDENTIAL_STRING_FIELDS: frozenset[str] = frozenset(
    {
        "acctserversecret",  # RADIUS accounting server secret (acctServerSecret)
        "authtoken",  # authToken
        "hashedpassword",  # hashedPassword
        "wpapsk",  # WLAN pre-shared key (wpaPsk)
    }
)

#: Pagination cursors: never credential fields, whatever the rules above would say
#: (``page_token`` / ``next_token`` end with the ``_token`` suffix). Matched
#: case-insensitively against the exact key name.
CURSOR_FIELDS: frozenset[str] = frozenset(
    {
        "nexttoken",
        "next_token",
        "pagetoken",
        "page_token",
        "continuationtoken",
        "continuation_token",
    }
)

#: Opt-in rule 2: a key ending with one of these snake_case suffixes (case-insensitive)
#: is a credential when its value is a string. The underscore is part of the suffix, so
#: camelCase identifiers such as Protect ``profileToken`` (a stream-profile id) and
#: ``digitalInputTokens`` are never matched, and neither are ``token_count`` / ``key_id``.
CREDENTIAL_SUFFIXES: tuple[str, ...] = (
    "_api_key",
    "_private_key",
    "_secret",
    "_token",
    "_password",
    "_passphrase",
)

#: Opt-in rule 3: the controller prefixes its hidden fields with ``x_``; such a key is a
#: credential when its name ends with one of these (case-insensitive) and its value is a
#: string. Derived from :data:`CREDENTIAL_FIELDS` and the ``x_`` keys in
#: ``tests/fixtures/recorded``. Matched there: ``x_iapp_key``, ``x_authkey``,
#: ``x_inform_authkey``, ``x_vwirekey``, ``x_mgmt_key``, ``x_private_key``,
#: ``x_wireguard_private_key``, ``x_pregenerated_dh_key``, ``x_stripe_api_key``,
#: ``x_quickpay_apikey``, ``x_merchantwarrior_apikey``, ``x_authorize_transactionkey``,
#: ``x_mesh_psk``, ``x_element_psk``, ``x_passphrase``,
#: ``x_merchantwarrior_apipassphrase``, ``x_password``, ``x_paypal_password``,
#: ``x_ssh_password``, ``x_ssh_sha512passwd``, ``x_secret``, ``x_api_token``,
#: ``x_sso_token``, ``x_paypal_signature``; VPN clients (r18 list_vpn_clients /
#: create_vpn_client) add ``x_wireguard_private_key`` and ``x_openvpn_password``.
#: Left verbatim: identifiers and flags (``x_ssh_username``, ``x_paypal_username``,
#: ``x_quickpay_merchantid``,
#: ``x_quickpay_agreementid``, ``x_authorize_loginid``, ``x_ippay_terminalid``,
#: ``x_merchantwarrior_merchantuuid``, ``x_mesh_essid``, ``x_element_essid``,
#: ``x_ssh_enabled``, ``x_ssh_bind_wildcard``, ``x_ssh_auth_password_enabled``,
#: ``x_aes_gcm``), public material (``x_certificate_pem``, ``x_certificate_arn``,
#: ``x_ssh_keys`` authorized public keys, ``x_ssh_hostkey_fingerprint``) and ``x_has_``
#: presence flags (``x_has_ssh_hostkey``).
X_FIELD_CREDENTIAL_ENDINGS: tuple[str, ...] = (
    "key",
    "psk",
    "passphrase",
    "password",
    "passwd",
    "secret",
    "token",
    "signature",
)


def _is_pattern_credential_key(lowered: str) -> bool:
    """Rules 2 and 3 on an already lower-cased key (value type checked by the caller)."""
    if lowered.endswith(CREDENTIAL_SUFFIXES):
        return True
    return (
        lowered.startswith("x_")
        and not lowered.startswith("x_has_")
        and lowered.endswith(X_FIELD_CREDENTIAL_ENDINGS)
    )


def is_credential_field(key: Any) -> bool:
    """Return True if ``key`` names a credential field under any documented rule.

    This classifies the key only. :func:`redact_credentials` masks a rule 2 or 3 match
    only when its value is a string; callers that inspect values apply the same gate.
    """
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in CURSOR_FIELDS:
        return False
    return (
        lowered in CREDENTIAL_FIELDS
        or lowered in CREDENTIAL_STRING_FIELDS
        or _is_pattern_credential_key(lowered)
    )


def _is_empty(value: Any) -> bool:
    """True for a value that holds nothing to mask: null or the empty string."""
    return value is None or value == ""


def _should_mask(key: Any, value: Any) -> bool:
    """True when ``key: value`` is masked under ``UNIFI_REDACT_SECRETS``."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in CURSOR_FIELDS:
        return False
    if lowered in CREDENTIAL_FIELDS or lowered in CREDENTIAL_STRING_FIELDS:
        # Rule 1 (exact names): a null or empty value holds nothing to mask.
        if _is_empty(value):
            return False
        return lowered in CREDENTIAL_FIELDS or isinstance(value, str)
    return isinstance(value, str) and _is_pattern_credential_key(lowered)


def redact_credentials(obj: Any) -> Any:
    """Return a deep copy of ``obj`` with every documented credential field masked.

    Recurses through dicts, lists and tuples. The value of any key in
    :data:`CREDENTIAL_FIELDS`, and the string value of any key matching
    :data:`CREDENTIAL_SUFFIXES` or the ``x_`` rule, is replaced with
    :data:`REDACTION_MASK`; all other keys and values are preserved unchanged. The
    input object is never mutated.
    """
    if isinstance(obj, dict):
        return {
            k: (REDACTION_MASK if _should_mask(k, v) else redact_credentials(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_credentials(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_credentials(item) for item in obj)
    return obj


#: Additive key on a write tool's result listing the body fields that held exactly
#: :data:`REDACTION_MASK` and were therefore left out of the upstream request.
MASKED_FIELDS_KEY = "_redactedFieldsNotSent"

#: Per tool call: the masked body-field paths the client dropped from its writes.
#: ``None`` outside a tool call (direct client use); the tool wrapper sets a fresh list.
_dropped_masked_fields: ContextVar[list[str] | None] = ContextVar(
    "unifi_dropped_masked_fields", default=None
)


_write_redaction: ContextVar[bool | None] = ContextVar("unifi_write_redaction", default=None)


def write_redaction_enabled() -> bool:
    """Use the enclosing tool/client setting, or the explicit environment opt-in."""
    enabled = _write_redaction.get()
    return env_flag("UNIFI_REDACT_SECRETS", False) if enabled is None else enabled


@contextmanager
def write_redaction_scope(enabled: bool) -> Iterator[None]:
    """Bind mask interpretation to the same setting as response redaction."""
    token = _write_redaction.set(enabled)
    try:
        yield
    finally:
        _write_redaction.reset(token)


class RedactionScopeMiddleware(Middleware):
    """Use the runtime setting for mask handling even before the tool handler runs."""

    def __init__(self, should_redact: Callable[[], bool]) -> None:
        self._should_redact = should_redact

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        with write_redaction_scope(self._should_redact()):
            return await call_next(context)


def drop_masked_fields(body: Any) -> tuple[Any, list[str]]:
    """Return ``(body without masked fields, dropped field paths)``.

    A read under ``UNIFI_REDACT_SECRETS`` returns credential fields as
    :data:`REDACTION_MASK`. Sending that object back to a write would overwrite the real
    secret with the literal mask, so every object field whose value is exactly the mask
    is left out of the request and the upstream keeps its stored value. Recurses through
    nested objects and lists; a list keeps every element (only object fields inside it
    are dropped). Paths are dotted with list indices in brackets (``radius.x_secret``,
    ``peers[0].private_key``). The input is never mutated; a body with no masked field
    is returned as the same object.
    """
    if not write_redaction_enabled():
        return body, []
    dropped: list[str] = []

    def walk(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            out: dict[Any, Any] = {}
            changed = False
            for k, v in node.items():
                child = f"{path}.{k}" if path else str(k)
                if isinstance(v, str) and v == REDACTION_MASK:
                    dropped.append(child)
                    changed = True
                    continue
                new_v = walk(v, child)
                changed = changed or new_v is not v
                out[k] = new_v
            return out if changed else node
        if isinstance(node, list):
            items = [walk(item, f"{path}[{i}]") for i, item in enumerate(node)]
            return items if any(a is not b for a, b in zip(items, node, strict=True)) else node
        return node

    return walk(body, ""), dropped


def note_dropped_fields(paths: list[str]) -> None:
    """Record masked field paths dropped from a write, for the current tool call."""
    sink = _dropped_masked_fields.get()
    if sink is not None:
        sink.extend(p for p in paths if p not in sink)


def drop_and_note_masked_fields(body: Any) -> Any:
    """:func:`drop_masked_fields` plus :func:`note_dropped_fields`; returns the clean body."""
    clean, dropped = drop_masked_fields(body)
    if dropped:
        note_dropped_fields(dropped)
    return clean


def _with_dropped_report(result: Any, dropped: list[str]) -> Any:
    """Add the dropped masked-field paths to a tool result (additive ``_`` key).

    An object result gains :data:`MASKED_FIELDS_KEY`. Bare arrays keep their shape:
    metadata goes on their object records, as with write warnings. An array containing
    only scalars (or no records) has nowhere for additive keys and stays unchanged.
    Other scalar results use the server's list envelope.
    """
    if not dropped:
        return result
    # Local import: the tools' client imports redaction during module initialization.
    from .tools._keys import with_context

    if isinstance(result, dict):
        return with_context(result, {MASKED_FIELDS_KEY: list(dropped)})
    if isinstance(result, list):
        return [
            with_context(record, {MASKED_FIELDS_KEY: list(dropped)})
            if isinstance(record, dict)
            else record
            for record in result
        ]
    return {"result": result, MASKED_FIELDS_KEY: list(dropped)}


_WRAPPED_FLAG = "_unifi_redaction_wrapped"


def _make_redacting_fn(
    fn: Callable[..., Any], should_redact: Callable[[], bool]
) -> Callable[..., Any]:
    """Wrap a tool handler so its result is redacted when ``should_redact()`` is True.

    ``should_redact`` is evaluated at call time, so toggling the setting takes effect
    without re-installing. When it returns False the handler result is returned
    unchanged (identity) — no transform, byte-identical output.

    The wrapper also collects, per call, the body fields the client left out of a write
    because they held exactly :data:`REDACTION_MASK` (see :func:`drop_masked_fields`)
    and reports them on the result under :data:`MASKED_FIELDS_KEY`. A call that dropped
    nothing is returned unchanged.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sink: list[str] = []
            token = _dropped_masked_fields.set(sink)
            try:
                with write_redaction_scope(should_redact()):
                    result = await fn(*args, **kwargs)
            finally:
                _dropped_masked_fields.reset(token)
            result = _with_dropped_report(result, sink)
            if should_redact():
                return redact_credentials(result)
            return result

        setattr(async_wrapper, _WRAPPED_FLAG, True)
        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        sink: list[str] = []
        token = _dropped_masked_fields.set(sink)
        try:
            with write_redaction_scope(should_redact()):
                result = fn(*args, **kwargs)
        finally:
            _dropped_masked_fields.reset(token)
        result = _with_dropped_report(result, sink)
        if should_redact():
            return redact_credentials(result)
        return result

    setattr(sync_wrapper, _WRAPPED_FLAG, True)
    return sync_wrapper


def install_response_redaction(mcp: Any, should_redact: Callable[[], bool]) -> int:
    """Install opt-in credential redaction at one shared point for EVERY tool.

    Wraps the handler of every registered tool so that, when ``should_redact()``
    returns True, the documented credential fields are masked in the response.
    Idempotent: a handler already wrapped is skipped. Returns the number of tool
    handlers wrapped. Relies only on the public ``fn`` attribute of each registered
    tool. If FastMCP internals change, an enabled redaction policy fails closed
    rather than silently leaving credentials visible.
    """
    try:
        components = mcp._local_provider._components  # noqa: SLF001
    except AttributeError:
        if should_redact():
            raise RuntimeError(
                "UNIFI_REDACT_SECRETS is enabled but tool handlers are unavailable; "
                "credential redaction could not be installed."
            ) from None
        return 0
    wrapped = 0
    protected = 0
    for component in components.values():
        fn = getattr(component, "fn", None)
        if fn is None or not callable(fn):
            continue
        if getattr(fn, _WRAPPED_FLAG, False):
            protected += 1
            continue
        component.fn = _make_redacting_fn(fn, should_redact)
        wrapped += 1
    if not (wrapped or protected) and should_redact():
        raise RuntimeError(
            "UNIFI_REDACT_SECRETS is enabled but no tool handlers could be protected; "
            "credential redaction could not be installed."
        )
    return wrapped
