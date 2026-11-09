"""API-source metadata and source selectors for UNIFI_EXCLUDE.

Each tool carries an internal metadata ID ``<app>/<source>/<access>``. Exclusion
configuration uses ``source:<app>`` or ``source:<app>/<source>``; the access
component is metadata, not accepted exclusion syntax. The components are:

* **app** - the product surface: ``network``, ``protect``, ``innerspace``,
  ``site_manager``, ``mobility``, ``carrier_fabric``, ``console`` (any other console
  application reached through the connector), ``relay`` (the generic connector relay
  tools) and ``server`` (a tool that makes no upstream request).
* **source** - ``official`` (a published Ubiquiti API: the specs pinned in
  ``tests/fixtures/spec_drift/baseline_snapshot.json``) or a private sub-surface of that
  app (the routes the controller web UIs call, no published spec):

  - ``network``: ``official`` (``/proxy/network/integration``), ``private.classic``
    (``/proxy/network/api/...``: ``api/s/<site>/rest|stat|cmd|set|list|group|upd``,
    ``api/self``, ``api/stat``), ``private.v2`` (``/proxy/network/v2/api``),
    ``private.other`` (any other Network route);
  - ``protect``: ``official`` (``/proxy/protect/integration``), ``private``
    (``/proxy/protect/api`` and every other non-integration Protect route);
  - ``innerspace``: ``official`` (``/proxy/innerspace/integration``), ``private``;
  - ``site_manager``: ``official`` for published ``api.ui.com/v1/...`` routes and
    ``private`` for the unpublished Early Access ``api.ui.com/ea/...`` surface;
  - ``mobility``, ``carrier_fabric``: ``official`` (Mobility under ``/v1/mobility``,
    Carrier Fabric under ``/v1/carrier``);
  - ``console``: ``private``; ``relay``: ``generic``; ``server``: ``local``.

* **access** - ``read`` or ``write``, taken from the tool's ``readOnlyHint`` annotation,
  which ``tests/test_tool_schema_contract.py`` pins equal to
  :func:`unifi_fabric._read_only_audit.derive_write_tools` (derived from source, never
  hand-listed). The one exception is the mixed GET relay (``SELECTED_AS_READ``): its
  ``readOnlyHint`` is false, but selection and the published class treat it as ``read``
  (:func:`selection_access`).

The (app, source) pairs a tool touches are DERIVED from the routes it calls:
``tests/api_sources_gen.py`` drives every registered tool against the hermetic fake
upstream, classifies every request path with :func:`route_source` and writes
``_api_source_table.py``; ``tests/test_api_sources.py`` re-derives it and fails on drift.
The generator also records explicit conservative per-tool overrides: the InnerSpace
asset tool belongs to the project surface, so disabling ``innerspace/private`` disables
it together with project and summary tools even when its asset request uses the official
route.
A tool's single class (:func:`primary_pair`) is the most private pair it touches; a tie
prefers the tool's own app over ``site_manager`` (console-id resolution through Site
Manager is shared infrastructure, not the tool's surface).

``UNIFI_EXCLUDE`` (opt-in; default unset) accepts comma-separated selectors:
``family:<id>``, ``tool:<name>``, ``source:<selector>`` and ``unofficial``.
Source selectors identify an app or app/source pair, for example ``source:network``
or ``source:network/private``; access-level selectors are not accepted. A matching
private pair or tracked substantive official dependency can also exclude a tool.
Use ``UNIFI_WRITE_POLICY`` or ``UNIFI_WRITE_EXCEPTIONS`` to control writes.
The helper filter functions in this module are test oracles; production uses policy.is_exposed.

The generic ``fabric_connector_*`` relay tools are ``relay/generic``. They can reach
any route, including private APIs, and are not removed by ``unofficial`` or private
source selectors. To exclude relay access too, use ``source:relay`` or
``source:relay/generic``. ``fabric_connector_get`` is selected as a read tool even
though its state-changing GET routes require write permission; use
``UNIFI_WRITE_POLICY=deny`` or ``UNIFI_WRITE_EXCEPTIONS=family:connector=deny``
to refuse those routes.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastmcp import FastMCP

_logger = logging.getLogger(__name__)

#: The opt-in environment variable naming selectors to disable.
DISABLE_ENV = "UNIFI_EXCLUDE"

OFFICIAL = "official"
PRIVATE = "private"
READ = "read"
WRITE = "write"
ACCESS: tuple[str, ...] = (READ, WRITE)
WILDCARD = "*"

#: app -> its sources, least private first.
APP_SOURCES: Mapping[str, tuple[str, ...]] = {
    "network": (OFFICIAL, "private.v2", "private.classic", "private.other"),
    "protect": (OFFICIAL, PRIVATE),
    "innerspace": (OFFICIAL, PRIVATE),
    "site_manager": (OFFICIAL, PRIVATE),
    "mobility": (OFFICIAL,),
    "carrier_fabric": (OFFICIAL,),
    "console": (PRIVATE,),
    "relay": ("generic",),
    "server": ("local",),
}
APPS: tuple[str, ...] = tuple(APP_SOURCES)

#: The metadata key carrying a tool's class id (``app/source/access``). The full set of
#: pairs a tool touches stays in the generated table (not on the wire: catalog budget).
META_CLASS = "unifi/apiSource"

#: Tools that select as a read although their annotation says write: the mixed GET relay.
#: Its state-changing GET routes are refused per call, not by a source selector.
SELECTED_AS_READ: frozenset[str] = frozenset({"fabric_connector_get"})

# Official APIs touched as substantive data dependencies by tools whose primary
# source is another app. Other secondary official pairs are shared identity
# resolution and do not participate in source selection.
TOOL_SUBSTANTIVE_SOURCES: Mapping[str, tuple[str, ...]] = {
    "get_unifi_placement_snapshot": ("protect/official",),
}

_CONSOLE_RE = re.compile(r"^/v1/connector/consoles/[^/]+/proxy/([^/?#]+)(?:/([^?#]*))?")
_PUBLISHED_INTEGRATION_APPS = frozenset({"network", "protect", "innerspace"})


def is_relay_tool(name: str) -> bool:
    """True for the generic connector relay tools."""
    return name.startswith("fabric_connector_")


def is_private(source: str) -> bool:
    """True for a private source (``private`` or ``private.<sub>``)."""
    return source == PRIVATE or source.startswith(PRIVATE + ".")


def route_source(path: str) -> str:
    """The ``app/source`` pair of one upstream request path (query string ignored)."""
    if not isinstance(path, str):
        raise TypeError(f"path must be a string, got {type(path).__name__}")
    bare = path.split("?", 1)[0]
    match = _CONSOLE_RE.match(bare)
    if match is None:
        if bare == "/ea" or bare.startswith("/ea/"):
            return "site_manager/private"
        if bare == "/v1/mobility" or bare.startswith("/v1/mobility/"):
            return "mobility/official"
        if bare == "/v1/carrier" or bare.startswith("/v1/carrier/"):
            return "carrier_fabric/official"
        return "site_manager/official"
    app, rest = match.group(1), (match.group(2) or "")
    integration = rest == "integration" or rest.startswith("integration/")
    if app in _PUBLISHED_INTEGRATION_APPS and integration:
        return f"{app}/official"
    if app == "network":
        if rest == "v2" or rest.startswith("v2/"):
            return "network/private.v2"
        if rest == "api" or rest.startswith("api/"):
            return "network/private.classic"
        return "network/private.other"
    if app in ("protect", "innerspace"):
        return f"{app}/private"
    return "console/private"


def _rank(pair: str) -> tuple[int, int]:
    app, source = pair.split("/", 1)
    privacy = APP_SOURCES[app].index(source) + (1 if is_private(source) else 0) * 10
    if app == "relay":
        privacy = 100
    # A tie prefers any app over site_manager (shared console-id resolution).
    return privacy, 0 if app == "site_manager" else 1


def tool_pairs(name: str, paths: Iterable[str]) -> tuple[str, ...]:
    """The ``app/source`` pairs a tool touches (sorted), from the paths it requested."""
    if is_relay_tool(name):
        return ("relay/generic",)
    found = {route_source(path) for path in paths}
    if not found:
        return ("server/local",)
    return tuple(sorted(found, key=lambda p: (_rank(p), p)))


def primary_pair(pairs: Iterable[str]) -> str:
    """A tool's single ``app/source``: the most private pair it touches."""
    items = list(pairs)
    if not items:
        raise ValueError("a tool touches at least one app/source pair")
    return max(items, key=lambda p: (_rank(p), p))


def class_id(pairs: Iterable[str], access: str) -> str:
    """The ``app/source/access`` id of a tool."""
    if access not in ACCESS:
        raise ValueError(f"access must be one of {', '.join(ACCESS)}, got {access!r}")
    return f"{primary_pair(pairs)}/{access}"


@dataclass(frozen=True)
class Selector:
    """One ``UNIFI_EXCLUDE`` entry: app (or ``*``), optional source, optional access."""

    app: str
    source: str | None = None
    access: str | None = None

    def matches(self, pair: str, access: str) -> bool:
        """True when this selector covers ``pair`` (``app/source``) with ``access``."""
        app, source = pair.split("/", 1)
        if self.app != WILDCARD and self.app != app:
            return False
        if self.source is not None and not (
            self.source == source or (self.source == PRIVATE and is_private(source))
        ):
            return False
        return self.access is None or self.access == access


def valid_selectors() -> tuple[str, ...]:
    """Every concrete selector (for error messages and docs), plus the wildcard forms."""
    out: list[str] = []
    for app, sources in APP_SOURCES.items():
        out.append(app)
        groups = list(sources)
        if any(is_private(s) for s in sources) and PRIVATE not in groups:
            groups.insert(1 if OFFICIAL in groups else 0, PRIVATE)
        for source in groups:
            out.append(f"{app}/{source}")
        for access in ACCESS:
            out.append(f"{app}/{access}")
    out.extend(f"{WILDCARD}/{source}" for source in (OFFICIAL, PRIVATE, "generic", "local"))
    out.extend(f"{WILDCARD}/{access}" for access in ACCESS)
    return tuple(out)


def _parse_selector(text: str) -> Selector | None:
    parts = text.split("/")
    access = None
    if len(parts) > 1 and parts[-1] in ACCESS:
        access = parts.pop()
    if not 1 <= len(parts) <= 2:
        return None
    app = parts[0]
    if app != WILDCARD and app not in APP_SOURCES:
        return None
    source = parts[1] if len(parts) == 2 else None
    if source is not None:
        if app == WILDCARD:
            known = {s for sources in APP_SOURCES.values() for s in sources} | {PRIVATE}
        else:
            known = set(APP_SOURCES[app])
            if any(is_private(s) for s in known):
                known.add(PRIVATE)
        if source not in known:
            return None
    if app == WILDCARD and source is None and access is None:
        return None  # a bare "*" would disable every tool: name what to disable
    return Selector(app=app, source=source, access=access)


def disabled_sources_problem(value: str | None) -> str | None:
    """Why a ``UNIFI_EXCLUDE`` value is invalid, or None.

    Entries are counted by position (from 0); their text is never shown, because a value
    set in the wrong variable may be a credential.
    """
    if value is None or not value.strip():
        return None
    parts = [part.strip().lower() for part in value.split(",")]
    unknown = [i for i, part in enumerate(parts) if part and _parse_selector(part) is None]
    valid = (
        "app, app/source or app/source/access (read|write), with * for every app; valid: "
        + ", ".join(valid_selectors())
        + " (and any app/source followed by /read or /write)"
    )
    if unknown:
        items = "item" if len(unknown) == 1 else "items"
        return (
            f"{DISABLE_ENV} names unknown selectors ({items} "
            f"{', '.join(str(i) for i in unknown)} of the comma-separated list, counted from "
            f"0; the value is not shown here); expected {valid}"
        )
    seen: set[str] = set()
    repeated: list[int] = []
    for i, part in enumerate(parts):
        if part and part in seen:
            repeated.append(i)
        seen.add(part)
    if repeated:
        items = "item" if len(repeated) == 1 else "items"
        return (
            f"{DISABLE_ENV} repeats a selector ({items} {', '.join(str(i) for i in repeated)}, "
            f"counted from 0); name each once. Expected {valid}"
        )
    return None


def parse_disabled_sources(value: str | None) -> tuple[Selector, ...]:
    """The selectors in ``UNIFI_EXCLUDE`` (empty/whitespace means none).

    Raises ``ValueError`` (never echoing the value) on an unknown or repeated selector,
    listing the valid selectors.
    """
    problem = disabled_sources_problem(value)
    if problem:
        raise ValueError(problem)
    if value is None or not value.strip():
        return ()
    out: list[Selector] = []
    for part in value.split(","):
        text = part.strip().lower()
        if text:
            selector = _parse_selector(text)
            assert selector is not None  # noqa: S101 - validated above
            out.append(selector)
    return tuple(out)


def is_disabled(
    pairs: Iterable[str],
    access: str,
    selectors: Iterable[Selector],
    *,
    tool_name: str | None = None,
) -> bool:
    """True when a tool (touched ``pairs``, ``access``) is covered by any selector.

    The tool's own class always counts; every other touched PRIVATE pair counts too (a
    tool that calls a disabled private surface is disabled). Official pairs touched for
    shared identity resolution do not count; explicitly tracked substantive dependencies do.
    The mixed GET relay is selected as a read. Action GETs through that relay are refused
    per call, and only by ``UNIFI_WRITE_POLICY=deny`` or the area opt-outs, not by a source
    selector.
    """
    if tool_name in SELECTED_AS_READ:
        access = READ
    items = list(pairs)
    considered = (
        {primary_pair(items)}
        | {p for p in items if is_private(p.split("/", 1)[1])}
        | set(TOOL_SUBSTANTIVE_SOURCES.get(tool_name or "", ()))
    )
    return any(sel.matches(pair, access) for sel in selectors for pair in considered)


def table() -> dict[str, tuple[str, ...]]:
    """The generated tool -> pairs table (``_api_source_table.TOOL_API_SOURCES``)."""
    from ._api_source_table import TOOL_API_SOURCES

    return dict(TOOL_API_SOURCES)


def tool_access(tool: Any) -> str:
    """``read`` or ``write`` from the tool's ``readOnlyHint`` annotation."""
    annotations = getattr(tool, "annotations", None)
    dump = getattr(annotations, "model_dump", None)
    wire = dump(by_alias=True) if callable(dump) else {}
    return READ if wire.get("readOnlyHint") is True else WRITE


def selection_access(tool: Any) -> str:
    """The access class used for selector filtering and the published class id.

    Equals :func:`tool_access` except for the mixed GET relay (``SELECTED_AS_READ``),
    which counts as a read, so the published ``unifi/apiSource`` class, the generated
    ``docs/TOOLS.md`` classes and selector filtering all agree.
    """
    if getattr(tool, "name", None) in SELECTED_AS_READ:
        return READ
    return tool_access(tool)


def counts(classes: Mapping[str, str]) -> dict[str, dict[str, int]]:
    """Tool counts per level from ``tool -> app/source/access`` ids.

    Returns ``{"app": {...}, "app/source": {...}, "app/source/access": {...},
    "app/access": {...}, "access": {...}}``.
    """
    out: dict[str, dict[str, int]] = {
        "app": {},
        "app/source": {},
        "app/source/access": {},
        "app/access": {},
        "access": {},
    }
    for cid in classes.values():
        app, source, access = cid.split("/")
        for level, key in (
            ("app", app),
            ("app/source", f"{app}/{source}"),
            ("app/source/access", cid),
            ("app/access", f"{app}/{access}"),
            ("access", access),
        ):
            out[level][key] = out[level].get(key, 0) + 1
    return {level: dict(sorted(values.items())) for level, values in out.items()}


def install_api_sources(mcp: Any) -> int:
    """Set the ``unifi/apiSource`` class id (``app/source/access``) metadata on every tool.

    Metadata only: names, schemas and behaviour are unchanged. A tool missing from the
    table keeps its metadata (the property test fails until the table is regenerated).
    Returns the number of tools labelled.
    """
    try:
        components = mcp._local_provider._components  # noqa: SLF001
    except AttributeError:  # pragma: no cover - defensive against FastMCP internals
        return 0
    data = table()
    labelled = 0
    for component in components.values():
        if not hasattr(component, "parameters"):
            continue
        pairs = data.get(component.name)
        if pairs is None:
            continue
        component.meta = {
            **(component.meta or {}),
            META_CLASS: class_id(pairs, selection_access(component)),
        }
        labelled += 1
    return labelled


async def apply_api_source_filter(mcp: FastMCP, value: str | None) -> list[str]:
    """De-register every tool covered by ``UNIFI_EXCLUDE`` (see :func:`is_disabled`).

    No-op when unset or blank (every source enabled, the default). Returns the removed
    tool names. A tool missing from the table logs a classification error and is treated
    as a write under ``*/write`` even when its annotation claims it is read-only.
    """
    selectors = parse_disabled_sources(value)
    if not selectors:
        return []
    data = table()
    removed: list[str] = []
    for tool in list(await mcp.list_tools()):
        pairs = data.get(tool.name)
        if pairs is None:
            _logger.error(
                "API source classification missing for tool %s; treating as write", tool.name
            )
            disabled = any(
                sel.app == WILDCARD and sel.source is None and sel.access == WRITE
                for sel in selectors
            )
        else:
            disabled = is_disabled(pairs, selection_access(tool), selectors, tool_name=tool.name)
        if disabled:
            mcp.local_provider.remove_tool(tool.name)
            removed.append(tool.name)
    _logger.info("API sources disabled: selectors=%d removed=%d", len(selectors), len(removed))
    return removed
