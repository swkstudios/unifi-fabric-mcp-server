"""Policy: the operator settings grammar, the evaluator and the two policy records.

Four settings decide what a server exposes and how its writes behave:

* ``UNIFI_WRITE_POLICY`` = ``allow`` | ``dry-run`` | ``deny`` (unset: ``allow``).
* ``UNIFI_WRITE_EXCEPTIONS``: one semicolon list of ``<target>=deny|dry-run`` where the
  target is ``family:<family-id>`` or ``tool:<public-name>``. There is no allow exception.
* ``UNIFI_FAMILY_ALLOW``: a comma set of frozen family IDs (unset: every family).
* ``UNIFI_EXCLUDE``: one comma list of ``family:<id>``, ``tool:<name>``, ``source:<selector>``
  and ``unofficial``.

The write order is allow < dry-run < deny, and the strictest of the global policy and every
matching exception wins. Tokens are trimmed of ASCII whitespace; an empty, leading, trailing
or doubled separator is malformed; values and IDs are case-sensitive. A setting that is
present but blank fails startup naming the setting. No token ever removes a meta tool: the
discovery meta tools and ``list_configured_api_keys`` stay under the tool-mode rules only.

The same grammars serve the request headers (``X-UniFi-Write-Policy``,
``X-UniFi-Family-Allow`` and ``X-UniFi-Exclude``) through :func:`request_policy`, which
only ever tightens the operator policy.

The two policy records (``policy.startup`` and ``policy.refusal``) are fixed one-line JSON
objects written to stderr at every audit level, including off. They never carry a label,
key, fingerprint or header.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from functools import lru_cache
from typing import IO, Any, Final

from . import api_sources
from .contracts import EffectivePolicy, WritePolicy, canonical_policy_json, policy_digest
from .families import ALL_FAMILIES

WRITE_POLICY_ENV: Final = "UNIFI_WRITE_POLICY"
WRITE_EXCEPTIONS_ENV: Final = "UNIFI_WRITE_EXCEPTIONS"
FAMILY_ALLOW_ENV: Final = "UNIFI_FAMILY_ALLOW"
EXCLUDE_ENV: Final = "UNIFI_EXCLUDE"
POLICY_SETTINGS: Final = (WRITE_POLICY_ENV, WRITE_EXCEPTIONS_ENV, FAMILY_ALLOW_ENV, EXCLUDE_ENV)

WRITE_POLICY_HEADER: Final = "x-unifi-write-policy"
FAMILY_ALLOW_HEADER: Final = "x-unifi-family-allow"
EXCLUDE_HEADER: Final = "x-unifi-exclude"

#: The setting prefix every server setting shares; any other name under it is retired.
SETTING_PREFIX: Final = "UNIFI_"
#: The 0.7.1 settings migration guide, pinned to the release tag of the public repository.
#: The server carries no list of old names: the guide and the one-shot migrator hold them.
MIGRATION_URL: Final = (
    "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md"
)
#: The one-shot migrator, run from the same tag; it is not part of the installed package.
MIGRATION_COMMAND: Final = (
    "uv run https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/v0.7.1/"
    "tools/migrate-0.7.1-env.py <config file>"
)

WRITE_POLICIES: Final[tuple[WritePolicy, ...]] = ("allow", "dry-run", "deny")
EXCEPTION_VALUES: Final = ("deny", "dry-run")
_RANK: Final = {value: rank for rank, value in enumerate(WRITE_POLICIES)}
DEFAULT_WRITE_POLICY: Final[WritePolicy] = "allow"

#: The frozen family IDs (13). ``meta`` is reserved and never valid in any list.
FAMILIES: Final[frozenset[str]] = frozenset(ALL_FAMILIES)
META_FAMILY: Final = "meta"
#: The six meta tools: the five discovery tools plus the local-only key listing.
META_TOOL_NAMES: Final = frozenset(
    {
        "search_tools",
        "describe_tool",
        "call_read_tool",
        "call_write_tool",
        "list_tool_families",
        "list_configured_api_keys",
    }
)
UNOFFICIAL: Final = "unofficial"
#: API sources whose tools are local (neither official nor unofficial).
LOCAL_PAIRS: Final = frozenset({"server/local", "relay/generic"})

_ASCII_WS: Final = " \t\n\r\x0b\x0c"


class StartupRefusal(Exception):  # noqa: N818 - a refusal, not a bug
    """A setting refuses startup. ``token`` is the startup token, always the last line
    printed; ``explain`` also prints ``message`` on the line before it."""

    def __init__(self, token: str, message: str, *, explain: bool = False) -> None:
        super().__init__(message)
        self.token = token
        self.message = message
        self.explain = explain

    def stderr_text(self) -> str:
        """What a refused start writes to stderr: the message when ``explain`` is set,
        then the token on its own last line."""
        lines = [self.message, self.token] if self.explain else [self.token]
        return "\n".join(lines) + "\n"


class PolicyHeaderError(ValueError):
    """A request policy header is blank, malformed or repeated (``invalid_policy_header``)."""

    def __init__(self, header: str, message: str) -> None:
        super().__init__(message)
        self.header = header
        self.code = "invalid_policy_header"


class _GrammarError(ValueError):
    """Internal: a token list is malformed. ``token`` is shown only when safe to name."""

    def __init__(self, message: str, *, token: str | None = None) -> None:
        super().__init__(message)
        self.token = token


# --------------------------------------------------------------------------- catalog facts


@dataclass(frozen=True, slots=True)
class ToolFacts:
    """What the policy needs to know about one registered tool."""

    name: str
    family: str
    pairs: tuple[str, ...]
    access: str  # api_sources.READ or api_sources.WRITE (selection access)

    @property
    def is_meta(self) -> bool:
        return self.family == META_FAMILY

    @property
    def is_write(self) -> bool:
        return self.access == api_sources.WRITE

    @property
    def canonical_id(self) -> str:
        return f"{self.family}.{self.name}"

    @property
    def api_status(self) -> str:
        """``local``, ``official`` or ``unofficial``, from the tool's primary API source."""
        if not self.pairs:
            return "local" if self.is_meta else "unclassified"
        primary = api_sources.primary_pair(self.pairs)
        if primary in LOCAL_PAIRS:
            return "local"
        source = primary.split("/", 1)[1]
        return UNOFFICIAL if api_sources.is_private(source) else "official"


@dataclass(frozen=True)
class Catalog:
    """The registered roster as policy facts, keyed by public tool name."""

    tools: Mapping[str, ToolFacts]
    domain_names: frozenset[str] = field(init=False)
    meta_names: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        meta = frozenset(n for n, t in self.tools.items() if t.is_meta)
        object.__setattr__(self, "meta_names", meta)
        object.__setattr__(self, "domain_names", frozenset(self.tools) - meta)

    @classmethod
    def build(
        cls,
        *,
        families: Mapping[str, str],
        sources: Mapping[str, Iterable[str]],
        access: Mapping[str, str],
    ) -> Catalog:
        """Build facts for every name in ``access``. Meta tools take family ``meta``.

        A domain tool without a family or an API-source classification fails validation
        (``unclassified catalog entries fail validation``).
        """
        tools: dict[str, ToolFacts] = {}
        unclassified: list[str] = []
        for name, tool_access in access.items():
            pairs = tuple(sources.get(name, ()))
            if name in META_TOOL_NAMES or name == "execute":
                tools[name] = ToolFacts(name, META_FAMILY, pairs, tool_access)
                continue
            family = families.get(name)
            if family is None or family not in FAMILIES or not pairs:
                unclassified.append(name)
                continue
            tools[name] = ToolFacts(name, family, pairs, tool_access)
        if unclassified:
            raise ValueError(
                f"{len(unclassified)} registered tools have no family or API-source "
                f"classification: {', '.join(sorted(unclassified)[:10])}"
            )
        return cls(tools=tools)

    @classmethod
    def for_names(cls, names: Iterable[str]) -> Catalog:
        """A name-only catalog: enough to validate ``tool:`` targets at startup."""
        return cls(
            tools={
                name: ToolFacts(name, META_FAMILY if name in META_TOOL_NAMES else "", (), "read")
                for name in names
            }
        )

    def canonical_id(self, name: str) -> str | None:
        facts = self.tools.get(name)
        return facts.canonical_id if facts is not None else None


# --------------------------------------------------------------------------- grammar


def _strip(value: str) -> str:
    return value.strip(_ASCII_WS)


def _is_blank(value: str) -> bool:
    return _strip(value) == ""


def _tokens(value: str, separator: str) -> list[str]:
    """Split a non-blank list; every token is trimmed and must be nonempty and unique."""
    parts = [_strip(part) for part in _strip(value).split(separator)]
    empty = [i for i, part in enumerate(parts) if not part]
    if empty:
        raise _GrammarError(
            f"has an empty item (position {', '.join(map(str, empty))}, counted from 0): "
            f"an empty, leading, trailing or doubled '{separator}' is malformed"
        )
    seen: set[str] = set()
    for i, part in enumerate(parts):
        if part in seen:
            raise _GrammarError(f"repeats an item (position {i}, counted from 0); name each once")
        seen.add(part)
    return parts


def _family_id(text: str, position: int) -> str:
    if text not in FAMILIES:
        raise _GrammarError(
            f"names an unknown or reserved family (position {position}, counted from 0); "
            f"valid families: {', '.join(sorted(FAMILIES))}"
        )
    return text


def _tool_target(name: str, token: str, position: int, catalog: Catalog | None) -> str:
    if name in META_TOOL_NAMES:
        raise _GrammarError(
            f"targets the meta tool in {token!r}; meta tools follow UNIFI_TOOL_MODE only",
            token=token,
        )
    if catalog is not None and name not in catalog.domain_names:
        raise _GrammarError(
            f"names an unknown tool (position {position}, counted from 0); use a public "
            "tool name from list_tool_families or docs/TOOLS.md"
        )
    return name


_VALID_SELECTORS: Final = frozenset(api_sources.valid_selectors())


def parse_write_policy(value: str) -> WritePolicy:
    """One of allow, dry-run, deny (trimmed, case-sensitive)."""
    text = _strip(value)
    for policy in WRITE_POLICIES:
        if text == policy:
            return policy
    raise _GrammarError(f"must be one of {', '.join(WRITE_POLICIES)} (case-sensitive)")


def parse_write_exceptions(value: str, catalog: Catalog | None) -> tuple[tuple[str, str], ...]:
    """The ``<target>=deny|dry-run`` pairs, sorted by target."""
    out: dict[str, str] = {}
    for i, token in enumerate(_tokens(value, ";")):
        target, sep, mode = token.partition("=")
        if not sep or mode not in EXCEPTION_VALUES:
            raise _GrammarError(
                f"item {i} (counted from 0) must be <target>=deny or <target>=dry-run; "
                "there is no allow exception"
            )
        kind, colon, ident = target.partition(":")
        if not colon:
            raise _GrammarError(f"item {i} target must be family:<id> or tool:<name>")
        if kind == "family":
            _family_id(ident, i)
        elif kind == "tool":
            _tool_target(ident, target, i, catalog)
        else:
            raise _GrammarError(f"item {i} target must be family:<id> or tool:<name>")
        if target in out:
            raise _GrammarError(f"item {i} repeats a target; name each target once")
        out[target] = mode
    return tuple(sorted(out.items()))


def parse_family_allow(value: str) -> tuple[str, ...]:
    """The family IDs in list order."""
    return tuple(_family_id(token, i) for i, token in enumerate(_tokens(value, ",")))


def parse_exclude(value: str, catalog: Catalog | None) -> tuple[str, ...]:
    """The exclusion tokens in list order."""
    out: list[str] = []
    for i, token in enumerate(_tokens(value, ",")):
        if token == UNOFFICIAL:
            out.append(token)
            continue
        kind, colon, ident = token.partition(":")
        if not colon:
            raise _GrammarError(
                f"item {i} (counted from 0) must be family:<id>, tool:<name>, "
                "source:<selector> or unofficial"
            )
        if kind == "family":
            _family_id(ident, i)
        elif kind == "tool":
            _tool_target(ident, token, i, catalog)
        elif kind == "source":
            if ident not in _VALID_SELECTORS:
                raise _GrammarError(
                    f"item {i} names an unknown API-source selector (case-sensitive); "
                    f"valid: {', '.join(sorted(_VALID_SELECTORS))}"
                )
        else:
            raise _GrammarError(
                f"item {i} must be family:<id>, tool:<name>, source:<selector> or unofficial"
            )
        out.append(token)
    return tuple(out)


def _family_exclusions(tokens: Iterable[str]) -> frozenset[str]:
    return frozenset(t.split(":", 1)[1] for t in tokens if t.startswith("family:"))


# --------------------------------------------------------------------------- operator


def unknown_settings(environ: Mapping[str, str], known: Iterable[str]) -> list[str]:
    """Sorted ``UNIFI_*`` names (prefix matched in any letter case) that are not current
    settings spelled exactly in their canonical upper case."""
    allowed = set(known) | set(POLICY_SETTINGS)
    return sorted(n for n in environ if n.upper().startswith(SETTING_PREFIX) and n not in allowed)


def _product() -> str:
    """``unifi-fabric-mcp <version>``, or the bare name in a checkout without metadata."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"unifi-fabric-mcp {version('unifi-fabric-mcp-server')}"
    except PackageNotFoundError:
        return "unifi-fabric-mcp"


def check_retired_settings(environ: Mapping[str, str], known: Iterable[str]) -> None:
    """Refuse startup on any non-current ``UNIFI_*`` name, naming it, never its value.

    The settings loader matches names in any letter case, so a lower- or mixed-case
    spelling fails closed too: a current setting in the wrong case fails as
    ``startup:<SETTING>``, and any other name as ``startup:retired:<SETTING>`` (the first
    in sorted order). The retired refusal's message names every unrecognized setting, all
    taken from the environment (this module lists no old names), and points to the
    migration guide and the one-shot migrator.
    """
    allowed = set(known) | set(POLICY_SETTINGS)
    unknown = unknown_settings(environ, allowed)
    if not unknown:
        return
    name = unknown[0]
    canonical = name.upper()
    more = f" (and {len(unknown) - 1} more)" if len(unknown) > 1 else ""
    if canonical in allowed:
        raise StartupRefusal(
            f"startup:{canonical}",
            f"{canonical} is set with a non-canonical letter case{more}; spell it in upper case.",
        )
    names = ", ".join(unknown)  # as spelled in the environment
    raise StartupRefusal(
        f"startup:retired:{canonical}",
        f"{_product()}: unrecognized settings: {names}. Settings "
        "were renamed in 0.7.1 and the old names are not accepted. Migrate: "
        f"{MIGRATION_URL} (one command: {MIGRATION_COMMAND})",
        explain=True,
    )


def _startup(setting: str, problem: str) -> StartupRefusal:
    return StartupRefusal(f"startup:{setting}", f"{setting} {problem}", explain=True)


def operator_policy(environ: Mapping[str, str], catalog: Catalog | None) -> EffectivePolicy:
    """The operator's EffectivePolicy from the four settings, or :class:`StartupRefusal`.

    An absent setting takes its default; a present but blank one fails startup naming
    the setting; a malformed one fails naming the setting and the problem, never echoing
    the value except a ``tool:<meta-name>`` target, which is named. With ``catalog``
    None, a ``tool:`` target is checked for form only (the startup check names unknowns).
    """
    parsed: dict[str, Any] = {}
    parsers = {
        WRITE_POLICY_ENV: parse_write_policy,
        WRITE_EXCEPTIONS_ENV: lambda v: parse_write_exceptions(v, catalog),
        FAMILY_ALLOW_ENV: parse_family_allow,
        EXCLUDE_ENV: lambda v: parse_exclude(v, catalog),
    }
    for setting, parse in parsers.items():
        if setting not in environ:
            continue
        value = environ[setting]
        if _is_blank(value):
            raise _startup(setting, "is set but blank; unset it for the default or give a value")
        try:
            parsed[setting] = parse(value)
        except _GrammarError as exc:
            raise _startup(setting, str(exc)) from None
    allowed = frozenset(parsed.get(FAMILY_ALLOW_ENV, FAMILIES))
    exclusions = frozenset(parsed.get(EXCLUDE_ENV, ()))
    return EffectivePolicy(
        write_policy=parsed.get(WRITE_POLICY_ENV, DEFAULT_WRITE_POLICY),
        write_exceptions=parsed.get(WRITE_EXCEPTIONS_ENV, ()),
        exposed_families=allowed - _family_exclusions(exclusions),
        exclusions=exclusions,
    )


# --------------------------------------------------------------------------- runtime

_runtime_catalog: Catalog | None = None
_runtime_cache: dict[tuple[str | None, ...], EffectivePolicy] = {}
_startup_policy: EffectivePolicy | None = None


def install_catalog(catalog: Catalog | None, startup: EffectivePolicy | None = None) -> None:
    """Validate ``tool:`` targets against ``catalog`` from now on (set at startup), and keep
    the startup policy whose exposure the fail-closed policy preserves."""
    global _runtime_catalog, _startup_policy
    _runtime_catalog = catalog
    _startup_policy = startup
    _runtime_cache.clear()


def fail_closed_policy() -> EffectivePolicy:
    """The policy used when the settings became malformed after startup: the startup
    exposure (``exposed_families`` and ``exclusions``) with every write denied."""
    if _startup_policy is None:
        return FAIL_CLOSED
    return replace(_startup_policy, write_policy="deny", write_exceptions=())


#: The policy a call runs under when the environment's policy settings became malformed
#: after startup and no startup policy was recorded: every write is denied (fail closed),
#: reads keep working. With a startup policy, :func:`fail_closed_policy` keeps its exposure.
FAIL_CLOSED: Final = EffectivePolicy("deny", (), FAMILIES, frozenset())
_fail_closed_reported: set[str] = set()


def current() -> EffectivePolicy:
    """The operator policy of the current environment, read now (cached per value).

    The server validates the settings once before startup (:func:`startup_gate` in
    :mod:`unifi_fabric.config`) and against the registered catalog in the lifespan; the
    call-time read keeps write decisions on the environment the process runs with. It never
    raises: a setting made malformed after startup fails closed to
    :func:`fail_closed_policy` (the startup exposure, every write denied) and its startup
    token is written to stderr once, so no broad ``except`` around a write path can swallow
    the decision.
    """
    values = tuple(os.environ.get(name) for name in POLICY_SETTINGS)
    cached = _runtime_cache.get(values)
    if cached is None:
        env = {
            name: value
            for name, value in zip(POLICY_SETTINGS, values, strict=True)
            if value is not None
        }
        try:
            cached = operator_policy(env, _runtime_catalog)
        except StartupRefusal as exc:
            if exc.token not in _fail_closed_reported:
                _fail_closed_reported.add(exc.token)
                print(exc.token, file=sys.stderr, flush=True)
            cached = fail_closed_policy()
        if len(_runtime_cache) > 64:
            _runtime_cache.clear()
        _runtime_cache[values] = cached
    return cached


# --------------------------------------------------------------------------- upstream count

_upstream_calls: ContextVar[list[int] | None] = ContextVar("policy_upstream_calls", default=None)


@contextmanager
def upstream_call_scope() -> Iterator[list[int]]:
    """Count the upstream requests one tool call sends (``policy.refusal`` upstream_calls)."""
    counter = [0]
    token = _upstream_calls.set(counter)
    try:
        yield counter
    finally:
        _upstream_calls.reset(token)


def note_upstream_call() -> None:
    """Record one upstream request at the client chokepoint (no-op outside a call scope)."""
    counter = _upstream_calls.get()
    if counter is not None:
        counter[0] += 1


def upstream_calls() -> int:
    """Upstream requests the current tool call has sent so far (0 outside a scope)."""
    counter = _upstream_calls.get()
    return counter[0] if counter is not None else 0


def family_exception(policy: EffectivePolicy, family: str | None) -> WritePolicy | None:
    """The ``family:<family>`` exception value, else None."""
    if family is None:
        return None
    for target, value in policy.write_exceptions:
        if target == f"family:{family}":
            return value  # type: ignore[return-value]
    return None


# --------------------------------------------------------------------------- request headers


def _header_value(header: str, value: str | None) -> str | None:
    if value is None:
        return None
    if _is_blank(value):
        raise PolicyHeaderError(header, f"{header} is present but blank")
    return value


def _parse_header(header: str, parse: Any, raw: str) -> Any:
    try:
        return parse(raw)
    except _GrammarError as exc:
        raise PolicyHeaderError(header, f"{header} {exc}") from None


def request_policy(
    operator: EffectivePolicy,
    catalog: Catalog,
    *,
    write_policy: str | None = None,
    family_allow: str | None = None,
    exclude: str | None = None,
) -> tuple[EffectivePolicy, tuple[str, ...]]:
    """Tighten ``operator`` by the request headers; return the policy and ignored loosening.

    ``None`` means the header is absent. The caller refuses a repeated header before this
    call. Write policy is the strictest of both; a looser request value is ignored and
    recorded. Family allow intersects the operator's exposed set; names outside it are
    ignored and recorded in header order. Exclusions unite. Requests add no exceptions.
    """
    ignored: list[str] = []
    policy = operator.write_policy
    families = set(operator.exposed_families)
    tokens: tuple[str, ...] = ()
    raw = _header_value(WRITE_POLICY_HEADER, write_policy)
    if raw is not None:
        requested = _parse_header(WRITE_POLICY_HEADER, parse_write_policy, raw)
        if _RANK[requested] < _RANK[policy]:
            ignored.append(f"{WRITE_POLICY_HEADER}={requested}")
        else:
            policy = requested
    raw = _header_value(FAMILY_ALLOW_HEADER, family_allow)
    if raw is not None:
        requested_families = _parse_header(FAMILY_ALLOW_HEADER, parse_family_allow, raw)
        ignored.extend(
            f"{FAMILY_ALLOW_HEADER}={f}" for f in requested_families if f not in families
        )
        families &= set(requested_families)
    raw = _header_value(EXCLUDE_HEADER, exclude)
    if raw is not None:
        tokens = _parse_header(EXCLUDE_HEADER, lambda v: parse_exclude(v, catalog), raw)
    exclusions = operator.exclusions | frozenset(tokens)
    effective = EffectivePolicy(
        write_policy=policy,
        write_exceptions=operator.write_exceptions,
        exposed_families=frozenset(families) - _family_exclusions(tokens),
        exclusions=exclusions,
    )
    return effective, tuple(ignored)


# --------------------------------------------------------------------------- decisions


@lru_cache(maxsize=256)
def _selectors_for(exclusions: frozenset[str]) -> tuple[api_sources.Selector, ...]:
    """Parse the source: tokens once per exclusion set; fail closed on an unparsable one."""
    out = []
    for token in sorted(exclusions):
        if token.startswith("source:"):
            selector = api_sources._parse_selector(token.split(":", 1)[1])  # noqa: SLF001
            if selector is None:
                raise ValueError("an exclusion carries an unparsable source: token")
            out.append(selector)
    return tuple(out)


def _selectors(policy: EffectivePolicy) -> tuple[api_sources.Selector, ...]:
    return _selectors_for(policy.exclusions)


def is_exposed(policy: EffectivePolicy, tool: ToolFacts) -> bool:
    """True when ``tool`` is listed and callable under ``policy``. Meta tools always are."""
    if tool.is_meta:
        return True
    if tool.family not in policy.exposed_families:
        return False
    if f"tool:{tool.name}" in policy.exclusions:
        return False
    if UNOFFICIAL in policy.exclusions and tool.api_status == UNOFFICIAL:
        return False
    selectors = _selectors(policy)
    return not (
        selectors
        and api_sources.is_disabled(tool.pairs, tool.access, selectors, tool_name=tool.name)
    )


def exposed_names(policy: EffectivePolicy, catalog: Catalog) -> frozenset[str]:
    """Every public name exposed under ``policy`` (meta tools included)."""
    return frozenset(name for name, facts in catalog.tools.items() if is_exposed(policy, facts))


def write_mode(policy: EffectivePolicy, *, tool_name: str, family: str) -> WritePolicy:
    """The strictest of the global policy and the exceptions matching this tool."""
    mode: WritePolicy = policy.write_policy
    for target, value in policy.write_exceptions:
        if target in (f"family:{family}", f"tool:{tool_name}") and _RANK[value] > _RANK[mode]:  # type: ignore[index]
            mode = value  # type: ignore[assignment]
    return mode


def narrows(policy: EffectivePolicy) -> bool:
    """True when ``policy`` removes any tool family or holds any exclusion."""
    return policy.exposed_families != FAMILIES or bool(policy.exclusions)


#: Names the operator policy de-registered at startup (refused with tool_not_exposed).
_excluded_names: frozenset[str] = frozenset()


def excluded_names() -> frozenset[str]:
    """The tool names the active operator policy removed at startup."""
    return _excluded_names


def clear_exposure() -> None:
    """Forget the startup exclusions and the startup catalog (the lifespan ended)."""
    global _excluded_names
    _excluded_names = frozenset()
    install_catalog(None)


async def apply_exposure(mcp: Any, policy: EffectivePolicy) -> list[str]:
    """De-register every registered tool :func:`is_exposed` rejects; meta tools stay.

    A no-op (no family index build) unless the policy narrows the catalog. Returns the
    removed names, sorted, and remembers them for :func:`excluded_names`.
    """
    global _excluded_names
    _excluded_names = frozenset()
    if not narrows(policy):
        return []
    from .families import _list_tools, _remove_tool, build_family_index

    tools = await _list_tools(mcp)
    catalog = Catalog.build(
        families=build_family_index(),
        sources=api_sources.table(),
        access={tool.name: api_sources.selection_access(tool) for tool in tools},
    )
    removed = sorted(n for n, facts in catalog.tools.items() if not is_exposed(policy, facts))
    for name in removed:
        _remove_tool(mcp, name)
    _excluded_names = frozenset(removed)
    return removed


# --------------------------------------------------------------------------- records

STARTUP_EVENT: Final = "policy.startup"
REFUSAL_EVENT: Final = "policy.refusal"
RECORD_SCHEMA_VERSION: Final = "1"
REFUSAL_CODES: Final = frozenset(
    {
        "invalid_api_key_header",
        "invalid_policy_header",
        "missing_api_key_header",
        "key_label_not_allowed",
        "tool_not_exposed",
        "write_denied",
        "code_mode_invalid_source",
        "code_mode_busy",
        "credential_cache_saturated",
    }
)
_REQUEST_ID: Final = re.compile(r"[0-9a-f]{32}")
_TOOL_ID: Final = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")
STARTUP_FIELDS: Final = frozenset(
    {"schema_version", "timestamp_utc", "event", "effective_policy", "digest"}
)
REFUSAL_FIELDS: Final = frozenset(
    {"schema_version", "timestamp_utc", "event", "request_id", "tool_id", "code", "upstream_calls"}
)


def canonical_policy_object(policy: EffectivePolicy) -> dict[str, Any]:
    """The canonical policy object (the parsed :func:`canonical_policy_json`)."""
    result: dict[str, Any] = json.loads(canonical_policy_json(policy))
    return result


def _dumps(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def startup_record(policy: EffectivePolicy, *, timestamp_utc: str | None = None) -> str:
    """The one-line ``policy.startup`` record (no trailing newline)."""
    return _dumps(
        {
            "schema_version": RECORD_SCHEMA_VERSION,
            "timestamp_utc": timestamp_utc or _now(),
            "event": STARTUP_EVENT,
            "effective_policy": canonical_policy_object(policy),
            "digest": policy_digest(policy),
        }
    )


def refusal_record(
    *,
    request_id: str,
    tool_id: str | None,
    code: str,
    upstream_calls: int,
    timestamp_utc: str | None = None,
) -> str:
    """The one-line ``policy.refusal`` record (no trailing newline).

    ``code`` must be a closed pre-dispatch refusal code, ``request_id`` 32 lowercase hex
    and ``tool_id`` a canonical ``<family>.<name>`` id or None, so no request text can
    reach a record written at every log level.
    """
    if code not in REFUSAL_CODES:
        raise ValueError("code must be a closed pre-dispatch refusal code")
    if not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("request_id must be 32 lowercase hex characters")
    if tool_id is not None and not _TOOL_ID.fullmatch(tool_id):
        raise ValueError("tool_id must be a canonical <family>.<name> id or None")
    if (
        isinstance(upstream_calls, bool)
        or not isinstance(upstream_calls, int)
        or upstream_calls < 0
    ):
        raise ValueError("upstream_calls must be a non-negative integer")
    return _dumps(
        {
            "schema_version": RECORD_SCHEMA_VERSION,
            "timestamp_utc": timestamp_utc or _now(),
            "event": REFUSAL_EVENT,
            "request_id": request_id,
            "tool_id": tool_id,
            "code": code,
            "upstream_calls": upstream_calls,
        }
    )


_record_listener: Callable[[str], None] | None = None


def set_record_listener(listener: Callable[[str], None] | None) -> None:
    """Also hand every record written to the process stderr to ``listener`` (the audit
    stream), so a policy record reaches the audit sink byte-identical."""
    global _record_listener
    _record_listener = listener


def emit(record: str, stream: IO[str] | None = None) -> None:
    """Write one record line to stderr (or ``stream``) and flush. Independent of audit
    level. A record for the process stderr is also carried to the audit listener."""
    out = stream if stream is not None else sys.stderr
    try:
        out.write(record + "\n")
        out.flush()
    except (OSError, ValueError):
        # A closed or broken stderr must never turn a refusal into a crash.
        pass
    if stream is None and _record_listener is not None:
        try:
            _record_listener(record)
        except Exception:  # noqa: BLE001, S110 - the audit stream never breaks a refusal
            pass
