"""Request policy tightening: the request-header tightening contract.

A request may tighten, never loosen, the operator's policy with three HTTP headers that
use the operator policy grammars (:mod:`unifi_fabric.policy`): ``X-UniFi-Write-Policy``,
``X-UniFi-Family-Allow`` and ``X-UniFi-Exclude``. The write policy is the strictest of the
operator and request values, family sets intersect, exclusions unite and requests add no
write exceptions. Valid loosening is ignored and recorded in ``ignored_loosening``.

This module wires the policy evaluator into the request path:

- **Step (2) of the refusal order** runs inside the header-credential ingress
  (:func:`unifi_fabric.header_credentials.evaluate_call`) through
  :func:`header_credentials.set_request_policy_hook`, so a blank, malformed, invalid or
  repeated policy header refuses with ``invalid_policy_header`` after (1)
  ``invalid_api_key_header`` and before (3) ``missing_api_key_header`` and (4)
  ``key_label_not_allowed``. The hook's result becomes the RequestContext's
  ``effective_policy`` and ``ignored_loosening``.
- **Steps (5) and (6)**, ``tool_not_exposed`` and ``write_denied``, run in
  :class:`RequestPolicyMiddleware`, added after the ingress and before every tool guard,
  argument check and upstream call. Codes (7)-(8) belong to Code Mode and (9) to
  the header-credential lease, which is innermost.
- Under an effective ``dry-run`` a write is not refused: the call runs with the client's
  existing dry-run preview forced on for the request (:func:`request_dry_run_active`), so
  it returns the existing dry-run result and sends no upstream mutation.
- ``tools/list`` reads only the policy headers (never ``X-UniFi-Api-Key``). A bad policy
  header is a JSON-RPC error with code ``TOOLS_LIST_POLICY_ERROR_CODE`` whose ``data`` is
  the refusal object; otherwise the list keeps only the tools the request may call.
  Discovery ``search_tools`` and ``describe_tool``/``call_*_tool`` follow the same policy.
  ``initialize`` and ``ping`` never read these headers.

Discovery dispatch (``call_read_tool``/``call_write_tool``) re-enters the middleware for
its target, so nested calls are checked as direct ones. A refused call returns MCP
``isError`` with one text item ``{"error": {"code", "message"}}`` and never echoes a header
value or key.
"""

from __future__ import annotations

import contextvars
import json
import os
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp.shared.exceptions import MCPError

from . import api_sources
from . import header_credentials as hc
from . import policy as sp
from .contracts import TOOLS_LIST_POLICY_ERROR_CODE, EffectivePolicy

#: Codes evaluated by this module, in their place in the closed order.
TOOL_NOT_EXPOSED = "tool_not_exposed"
WRITE_DENIED = "write_denied"

#: Discovery tools whose ``name`` argument names the domain tool they act on, and the two
#: of them that execute it.
TARGETED_META_TOOLS = frozenset({"describe_tool", "call_read_tool", "call_write_tool"})
DISPATCH_TOOLS = frozenset({"call_read_tool", "call_write_tool"})

HeaderSource = Callable[[str], "list[str] | None"]
ToolsSource = Callable[[], Mapping[str, Any]]


def _refusal_text(code: str, message: str) -> str:
    return json.dumps({"error": {"code": code, "message": message}}, separators=(",", ":"))


def _record_refusal(name: str, code: str) -> None:
    """The one ``policy.refusal`` record of a step-(5)/(6) refusal (stderr and audit sink)."""
    from .read_only_tools import canonical_tool_id

    if code in sp.REFUSAL_CODES:
        sp.emit(
            sp.refusal_record(
                request_id=hc.current_request_id() or uuid.uuid4().hex,
                tool_id=canonical_tool_id(name),
                code=code,
                upstream_calls=sp.upstream_calls(),
            )
        )


def refusal_error(code: str, message: str) -> ToolError:
    """The MCP tool error of a pre-dispatch refusal: one text item, the refusal object."""
    return ToolError(_refusal_text(code, message))


def _not_exposed_message(name: str) -> str:
    return (
        f"{name!r} is not exposed under the effective policy for this request (operator "
        "family set and exclusions, narrowed by any X-UniFi-Family-Allow or X-UniFi-Exclude "
        "header). Use tools/list or search_tools to see the tools you can call."
    )


def _write_denied_message(name: str, entry: str | None = None) -> str:
    text = (
        f"{name!r} is a write and the effective write policy for this request denies it "
        "(UNIFI_WRITE_POLICY, UNIFI_WRITE_EXCEPTIONS or X-UniFi-Write-Policy). No upstream "
        "call was made."
    )
    if entry is not None:
        text += (
            f" The UNIFI_WRITE_EXCEPTIONS entry {entry} denies it. To allow it, remove that "
            "entry and restart the server (see Enabling / disabling connector writes in "
            "docs/CONFIGURATION.md#enabling--disabling-connector-writes)."
        )
    return text


def _denying_entry(policy: EffectivePolicy, *, tool_name: str, family: str) -> str | None:
    """The ``<target>=deny`` exception that denies the call, else None.

    None when the global policy itself denies (its message already names it).
    """
    if policy.write_policy == "deny":
        return None
    for target, value in policy.write_exceptions:
        if value == "deny" and target in (f"family:{family}", f"tool:{tool_name}"):
            return f"{target}={value}"
    return None


# --------------------------------------------------------------------------- catalog


def catalog_from_tools(tools: Iterable[Any]) -> sp.Catalog:
    """The policy catalog of the registered tools (families, API sources, access)."""
    from .families import build_family_index

    items = list(tools)
    table = api_sources.table()
    return sp.Catalog.build(
        families=build_family_index(),
        sources={t.name: table.get(t.name, ()) for t in items},
        access={t.name: api_sources.selection_access(t) for t in items},
    )


def local_tools(server: Any) -> dict[str, Any]:
    """The server's registered tools, read from its local provider.

    Reading the provider (not ``list_tools``) never re-enters a tools/list middleware.
    """
    components = server._local_provider._components  # noqa: SLF001
    return {c.name: c for c in components.values() if hasattr(c, "parameters")}


# --------------------------------------------------------------------------- evaluation


def tighten(
    headers: HeaderSource, operator: EffectivePolicy, catalog: sp.Catalog
) -> tuple[EffectivePolicy, tuple[str, ...]]:
    """The request's EffectivePolicy and ignored_loosening; :class:`sp.PolicyHeaderError`
    for a repeated, blank, malformed or invalid policy header (never merged)."""
    values: dict[str, str | None] = {}
    for header in (sp.WRITE_POLICY_HEADER, sp.FAMILY_ALLOW_HEADER, sp.EXCLUDE_HEADER):
        found = headers(header) or []
        if len(found) > 1:
            raise sp.PolicyHeaderError(
                header, f"{header} was sent more than once; send each policy header once."
            )
        values[header] = found[0] if found else None
    return sp.request_policy(
        operator,
        catalog,
        write_policy=values[sp.WRITE_POLICY_HEADER],
        family_allow=values[sp.FAMILY_ALLOW_HEADER],
        exclude=values[sp.EXCLUDE_HEADER],
    )


def call_target(name: str, arguments: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    """The tool a call acts on and its arguments (discovery dispatch unwrapped)."""
    if name in TARGETED_META_TOOLS:
        target = arguments.get("name")
        if isinstance(target, str):
            inner = arguments.get("arguments") if name in DISPATCH_TOOLS else {}
            return target, inner if isinstance(inner, Mapping) else {}
    return name, arguments


def decide(
    *,
    name: str,
    arguments: Mapping[str, Any],
    policy: EffectivePolicy,
    catalog: sp.Catalog,
    is_write: Callable[[str, Mapping[str, Any]], bool],
) -> tuple[str | None, str, str]:
    """Steps (5) and (6) for one call: ``(refusal code or None, message, write mode)``.

    ``write mode`` is the strictest of the global policy and the exceptions matching the
    target (``allow`` when the call does not write).
    """
    target, target_args = call_target(name, arguments)
    facts = catalog.tools.get(target)
    if facts is None or facts.is_meta:
        return None, "", "allow"  # unknown names keep their baseline error
    if not sp.is_exposed(policy, facts):
        return TOOL_NOT_EXPOSED, _not_exposed_message(target), "allow"
    executes = name not in TARGETED_META_TOOLS or name in DISPATCH_TOOLS
    if not executes or not is_write(target, target_args):
        return None, "", "allow"
    mode = sp.write_mode(policy, tool_name=target, family=facts.family)
    if mode == "deny":
        entry = _denying_entry(policy, tool_name=target, family=facts.family)
        return WRITE_DENIED, _write_denied_message(target, entry), mode
    return None, "", mode


# --------------------------------------------------------------------------- request state

_REQUEST_DRY_RUN: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "unifi_request_dry_run", default=False
)
_CATALOG: sp.Catalog | None = None


def request_dry_run_active() -> bool:
    """True while serving a write whose effective write mode is ``dry-run``."""
    return _REQUEST_DRY_RUN.get()


@contextmanager
def _dry_run(active: bool) -> Iterator[None]:
    token = _REQUEST_DRY_RUN.set(active or _REQUEST_DRY_RUN.get())
    try:
        yield
    finally:
        _REQUEST_DRY_RUN.reset(token)


def visible_to_request(name: str) -> bool:
    """False when the current request's policy hides tool ``name`` (discovery search)."""
    context = hc.current_request_context()
    if context is None or _CATALOG is None:
        return True
    facts = _CATALOG.tools.get(name)
    return facts is None or sp.is_exposed(context.effective_policy, facts)


# --------------------------------------------------------------------------- wiring


class RequestPolicy:
    """The per-server evaluator: catalog, operator policy and header source."""

    def __init__(
        self,
        tools: ToolsSource,
        *,
        operator: Callable[[sp.Catalog], EffectivePolicy] | None = None,
        headers: HeaderSource | None = None,
    ) -> None:
        self._tools = tools
        self._operator = operator or (lambda catalog: sp.operator_policy(os.environ, catalog))
        self._headers = headers
        self._catalog: sp.Catalog | None = None

    def tools(self) -> Mapping[str, Any]:
        return self._tools()

    def catalog(self) -> sp.Catalog:
        global _CATALOG
        if self._catalog is None:
            self._catalog = catalog_from_tools(self._tools().values())
            _CATALOG = self._catalog
        return self._catalog

    def header_source(self) -> HeaderSource:
        return self._headers or hc._raw_header_values  # noqa: SLF001 - the ingress source

    def operator(self) -> EffectivePolicy:
        return self._operator(self.catalog())

    def evaluate(
        self, headers: HeaderSource | None = None
    ) -> tuple[EffectivePolicy, tuple[str, ...]]:
        """Tighten the operator policy by the request headers (raises PolicyHeaderError)."""
        return tighten(headers or self.header_source(), self.operator(), self.catalog())

    def hook(self, headers: HeaderSource) -> tuple[EffectivePolicy, tuple[str, ...]]:
        """Step-(2) hook: the tightened policy, or an ``invalid_policy_header`` refusal."""
        try:
            return self.evaluate(headers)
        except sp.PolicyHeaderError as exc:
            raise hc.PreDispatchRefusal(hc.INVALID_POLICY_HEADER, str(exc)) from None

    def is_write(self, name: str, arguments: Mapping[str, Any]) -> bool:
        from .read_only_tools import is_write_tool_call

        tool = self._tools().get(name)
        return tool is not None and is_write_tool_call(tool, name, dict(arguments))


class RequestPolicyMiddleware(Middleware):
    """Steps (5) ``tool_not_exposed`` and (6) ``write_denied``, request dry-run, tools/list.

    Added after the ingress: the RequestContext it built carries the tightened policy. A
    call the ingress passes through without a context (no configured key: the tool reports it)
    evaluates the headers here, step (2) included.
    """

    def __init__(self, evaluator: RequestPolicy) -> None:
        self.evaluator = evaluator

    async def on_list_tools(self, context: MiddlewareContext, call_next: CallNext) -> Any:
        tools = await call_next(context)
        try:
            policy, _ignored = self.evaluator.evaluate()
        except sp.PolicyHeaderError as exc:
            message = str(exc)
            raise MCPError(
                code=TOOLS_LIST_POLICY_ERROR_CODE,
                message=message,
                data={"error": {"code": hc.INVALID_POLICY_HEADER, "message": message}},
            ) from None
        catalog = self.evaluator.catalog()
        return [
            tool
            for tool in tools
            if (facts := catalog.tools.get(tool.name)) is None or sp.is_exposed(policy, facts)
        ]

    async def on_call_tool(self, context: MiddlewareContext, call_next: CallNext) -> Any:
        name = context.message.name
        arguments = context.message.arguments or {}
        request = hc.current_request_context()
        if request is not None:
            policy = request.effective_policy
        else:
            try:
                policy, _ignored = self.evaluator.evaluate()
            except sp.PolicyHeaderError as exc:
                raise refusal_error(hc.INVALID_POLICY_HEADER, str(exc)) from None
        code, message, mode = decide(
            name=name,
            arguments=arguments,
            policy=policy,
            catalog=self.evaluator.catalog(),
            is_write=self.evaluator.is_write,
        )
        if code is not None:
            _record_refusal(name, code)
            raise refusal_error(code, message)
        with _dry_run(mode == "dry-run"):
            return await call_next(context)


def install(server: Any, *, headers: HeaderSource | None = None) -> RequestPolicy:
    """Create the evaluator for ``server``, register the ingress step-(2) hook, return it."""
    evaluator = RequestPolicy(lambda: local_tools(server), headers=headers)
    hc.set_request_policy_hook(evaluator.hook)
    return evaluator
