"""Systematic derivation of the write/action tool set for read-only coverage.

Rather than hand-maintaining a list of write tools — which rots the moment a new
mutating tool is added — this module *derives* the set from source. Starting at
each registered tool's implementation function, it follows the call graph (within
the ``unifi_fabric`` package, via each function's own ``__globals__``) and marks a
tool as a write/action tool when any reachable function issues a mutating upstream
call: a ``client.post/put/patch/delete`` (read-POSTs go through
``read_post_routes.post_read`` instead and are reads), a
``client.request("POST"/"PUT"/"PATCH"/"DELETE")``, the generic connector write
relay (``connector_write``), or a GET the upstream acts on (a function registered with
:func:`state_changing_get`).

The companion test (:mod:`tests.test_read_only`) asserts that every derived write
tool is covered by the central read-only guard, so a *new* write tool that routes
its mutation outside the guard fails CI — the whole point of deriving the set
instead of listing it.
"""

from __future__ import annotations

import ast
import functools
import inspect
import re
import textwrap
from collections.abc import Callable
from functools import lru_cache
from typing import Any

# A ``client.<verb>(`` call. ``post_multipart`` is a POST upload.
_WRITE_CALL_RE = re.compile(r"\.(post_multipart|post|put|patch|delete)\s*\(")
# A ``...request("VERB"`` / ``...request('VERB'`` call with a literal write verb.
_REQUEST_WRITE_RE = re.compile(r"""\.request\(\s*["'](POST|PUT|PATCH|DELETE)["']""")

# The generic connector relay issues a mutating ``client.request(method_u, ...)``
# with a *dynamic* method, so it is recognised by name rather than by a verb literal.
_RELAY_FUNC_NAMES = frozenset({"connector_write"})

# A Classic command POST that deletes controller state, e.g. the site manager's
# ``{"cmd": "delete-device", ...}`` (the UI's "Forget device"). It removes a record just as
# an HTTP DELETE does. Every write tool advertises ``destructiveHint=true``
# (tool_annotations.for_tool); this marks the subset that removes state, whose
# descriptions must state the consequence (tests/test_surface_guidance.py).
_DELETE_CMD_RE = re.compile(r"""["']cmd["']\s*:\s*["']delete-""")

#: Marker of a function that issues a state-changing GET: the upstream changes state on
#: a GET (a route on ``read_only.STATE_CHANGING_GET_ROUTES``, which the client chokepoint
#: already treats as a write). The source scan cannot see a route, so the function is
#: marked: the tool that reaches it is classified as a write action (verb ``POST``, the
#: action class every guard and annotation treats as a write) instead of a read. Set it
#: with :func:`state_changing_get`.
STATE_CHANGING_GET_ATTR = "__unifi_state_changing_get__"


def state_changing_get[F: Callable[..., Any]](fn: F) -> F:
    """Register ``fn`` as issuing a state-changing GET (see :data:`STATE_CHANGING_GET_ATTR`)."""
    setattr(fn, STATE_CHANGING_GET_ATTR, True)
    return fn


def _verb_of(match_text: str) -> str:
    v = match_text.upper()
    return "POST" if v.startswith("POST") else v


type _SourceFacts = tuple[frozenset[str], tuple[tuple[str, str | None], ...], bool]


@lru_cache(maxsize=8192)
def _source_facts(fn: Callable[..., Any]) -> _SourceFacts:
    # Registered callable identities keep shared helpers read-once without conflating
    # equal code objects. Fresh registrations re-read source, whose exact text keys
    # the syntax cache below. Leave unavailable-source exceptions uncached.
    return _cached_source_facts(inspect.getsource(getattr(fn, "__code__", fn)))


@lru_cache(maxsize=8192)
def _cached_source_facts(src: str) -> _SourceFacts:
    """Cache immutable syntax across reloads; resolve globals and markers fresh."""
    verbs = {_verb_of(match.group(1)) for match in _WRITE_CALL_RE.finditer(src)}
    verbs.update(match.group(1) for match in _REQUEST_WRITE_RE.finditer(src))
    try:
        tree = ast.parse(textwrap.dedent(src))
    except SyntaxError:
        return frozenset(verbs), (), bool(_DELETE_CMD_RE.search(src))
    calls: list[tuple[str, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name):
            calls.append((f.id, None))
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            calls.append((f.value.id, f.attr))
    return frozenset(verbs), tuple(calls), bool(_DELETE_CMD_RE.search(src))


def _direct_write_verbs(fn: Callable[..., Any]) -> set[str]:
    """Write verbs issued directly in ``fn``'s own body (read-POSTs excluded)."""
    if getattr(fn, "__unifi_read_post__", False):
        # This helper permits only allowlisted read-POSTs; other POSTs are writes.
        return set()
    # FastMCP wrappers have restricted globals: analyse the implementation.
    fn = inspect.unwrap(fn)
    verbs: set[str] = set()
    if getattr(fn, STATE_CHANGING_GET_ATTR, False):
        verbs.add("POST")
    try:
        source_verbs, _, _ = _source_facts(getattr(fn, "__func__", fn))
    except (OSError, TypeError):
        return verbs
    verbs.update(source_verbs)
    if fn.__name__ in _RELAY_FUNC_NAMES:
        verbs.update({"POST", "PUT", "PATCH", "DELETE"})
    return verbs


def _called_package_functions(fn: Callable[..., Any]) -> list[Callable[..., Any]]:
    """Resolve cached call syntax against this implementation's current globals."""
    fn = inspect.unwrap(fn)
    try:
        _, calls, _ = _source_facts(getattr(fn, "__func__", fn))
    except (OSError, TypeError):
        return []
    g = getattr(fn, "__globals__", {})
    out: list[Callable[..., Any]] = []
    for name, attribute in calls:
        obj = g.get(name)
        if attribute is not None and obj is not None:
            obj = getattr(obj, attribute, None)
        if callable(obj) and (getattr(obj, "__module__", "") or "").startswith("unifi_fabric"):
            out.append(obj)
    return out


def write_verbs_for(fn: Callable[..., Any]) -> set[str]:
    """Transitive set of write verbs reachable from ``fn`` (empty ⇒ read-only tool)."""
    verbs: set[str] = set()
    seen: set[Any] = set()
    stack: list[Callable[..., Any]] = [fn]
    while stack:
        cur = stack.pop()
        key = getattr(cur, "__code__", cur)
        if key in seen:
            continue
        seen.add(key)
        verbs |= _direct_write_verbs(cur)
        stack.extend(_called_package_functions(cur))
    return verbs


#: Source evidence that a function talks to the UniFi upstream: it obtains the client
#: through ``_require()`` or calls a method on a ``client``.
_UPSTREAM_RE = re.compile(r"\b_require\(|\bclient\.\w+\(")


@functools.cache
def _cached_reaches_upstream(src: str) -> bool:
    return bool(_UPSTREAM_RE.search(src))


def reaches_upstream(fn: Callable[..., Any]) -> bool:
    """Whether ``fn`` or a package function it calls (transitively) uses the UniFi client.

    The same call-graph walk as :func:`write_verbs_for`. A tool that only reads local
    configuration (``list_configured_api_keys``) or the local tool catalog (the discovery
    search and describe tools) does not reach the upstream.
    """
    seen: set[Any] = set()
    stack: list[Callable[..., Any]] = [fn]
    while stack:
        cur = stack.pop()
        key = getattr(cur, "__code__", cur)
        if key in seen:
            continue
        seen.add(key)
        target = inspect.unwrap(cur)
        try:
            src = inspect.getsource(getattr(target, "__func__", target))
        except (OSError, TypeError):
            continue
        if _cached_reaches_upstream(src):
            return True
        stack.extend(_called_package_functions(cur))
    return False


def classify_tool_verbs(tools: list[Any]) -> dict[str, set[str]]:
    """Map every registered tool name → the set of write verbs it can issue."""
    return {tool.name: write_verbs_for(tool.fn) for tool in tools}


def derive_write_tools(tools: list[Any]) -> set[str]:
    """Derive write/action names once per catalog, returning an independent set.

    Names and callable identities form an immutable key: listing/copying the same
    tools hits the cache, while filtering, renaming or replacing implementations
    recomputes it. Keep the callables themselves, not their ids (which can be reused
    after collection). Tool implementations and their call graphs are fixed for a
    registered catalog; reloaded/re-registered functions form a new catalog.
    """
    catalog = frozenset({tool.name: tool.fn for tool in tools}.items())
    return set(_derive_write_tools(catalog))


@lru_cache(maxsize=256)
def _derive_write_tools(catalog: frozenset[tuple[str, Callable[..., Any]]]) -> frozenset[str]:
    """Bound retained catalogs, and never expose a mutable cached result."""
    return frozenset(name for name, fn in catalog if write_verbs_for(fn))


def _direct_delete_command(fn: Callable[..., Any]) -> bool:
    """True when ``fn``'s own body builds a Classic ``delete-*`` command body."""
    fn = inspect.unwrap(fn)
    try:
        return _source_facts(getattr(fn, "__func__", fn))[2]
    except (OSError, TypeError):
        return False


def is_destructive(fn: Callable[..., Any]) -> bool:
    """True when ``fn`` can remove upstream state: an HTTP ``DELETE`` or a Classic
    ``delete-*`` command POST is reachable from it (transitively, like
    :func:`write_verbs_for`)."""
    if "DELETE" in write_verbs_for(fn):
        return True
    seen: set[Any] = set()
    stack: list[Callable[..., Any]] = [fn]
    while stack:
        cur = stack.pop()
        key = getattr(cur, "__code__", cur)
        if key in seen:
            continue
        seen.add(key)
        if _direct_delete_command(cur):
            return True
        stack.extend(_called_package_functions(cur))
    return False
