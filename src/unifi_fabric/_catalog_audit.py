"""Catalog regression audit: registered tools vs the deployed gateway catalog.

When this server is federated behind an MCP gateway, the gateway caches each tool's
name under a per-gateway *slug prefix* and re-exposes it to callers. That cached
listing — the **deployed catalog** — is what agents actually see and call. If a tool
is registered here (`@mcp.tool()` in ``server.py``) but missing from the deployed
catalog, it is unreachable; if the catalog carries a name that is no longer
registered here, it is a stale/phantom entry. Either direction is a silent
regression, because every static check in this repo introspects the *registered*
set and never compares it to what the gateway is actually serving.

This module holds the **pure, hermetic** comparison logic so it can run in CI with no
network and no credentials:

* :func:`federated_tool_name` — the exact ``registered -> catalog`` name transform the
  gateway applies (slug prefix + hyphenation).
* :func:`base_tool_name` — the inverse for a single gateway (``catalog -> registered``),
  returning ``None`` for a name that does not belong to the given slug.
* :func:`extract_catalog_names` — pull the tool-name list out of the shapes a catalog
  snapshot can arrive in (a bare name list, an MCP ``tools/list`` result, or a
  ``{"data": [...]}`` envelope).
* :func:`diff_catalog` — registered set vs catalog set for one gateway, reported as a
  :class:`CatalogDiff` naming exactly what is missing from the catalog and what is
  present in the catalog but unregistered.

The **live** fetch of a real deployed catalog is deliberately NOT here — it lives in
``scripts/check_catalog_regression.py`` and the integration-marked test — so this
module stays free of I/O and is fully unit-testable. The default slug is the dev
gateway's; callers pass the prod slug (or any other) explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# Default federation slug for the development gateway. Prod (and any other gateway)
# is passed explicitly by the caller; this default only spares the common dev case.
DEFAULT_GATEWAY_SLUG = "unifi-fabric-dev"


def federated_tool_name(registered_name: str, gateway_slug: str = DEFAULT_GATEWAY_SLUG) -> str:
    """Return the name the gateway federates ``registered_name`` under.

    The gateway prefixes the gateway slug and renders the whole identifier hyphenated,
    so ``("list_lags", "unifi-fabric-dev")`` becomes ``"unifi-fabric-dev-list-lags"``.
    Registered names are snake_case Python identifiers (never contain a hyphen), which
    is what makes the transform losslessly invertible by :func:`base_tool_name`.
    """
    return f"{gateway_slug}-{registered_name.replace('_', '-')}"


def base_tool_name(catalog_name: str, gateway_slug: str = DEFAULT_GATEWAY_SLUG) -> str | None:
    """Invert :func:`federated_tool_name` for one gateway.

    Returns the registered-style (snake_case) base name, or ``None`` when
    ``catalog_name`` does not carry this gateway's slug prefix (i.e. it belongs to a
    different federated gateway and must not be compared against this server).
    """
    prefix = f"{gateway_slug}-"
    if not catalog_name.startswith(prefix):
        return None
    return catalog_name[len(prefix) :].replace("-", "_")


def catalog_base_names(
    catalog_names: Iterable[str], gateway_slug: str = DEFAULT_GATEWAY_SLUG
) -> set[str]:
    """Return the registered-style base names for one gateway from a catalog listing.

    Names belonging to other gateways (no matching slug prefix) are dropped, so a
    full multi-gateway catalog can be passed and only this server's entries compared.
    """
    result: set[str] = set()
    for name in catalog_names:
        base = base_tool_name(name, gateway_slug)
        if base is not None:
            result.add(base)
    return result


def extract_catalog_names(payload: object) -> list[str]:
    """Extract tool names from the shapes a catalog snapshot can arrive in.

    Accepts:
      * a bare list of name strings (``["gw-list_x", ...]``),
      * an MCP ``tools/list`` result (``{"result": {"tools": [{"name": ...}]}}`` or the
        already-unwrapped ``{"tools": [{"name": ...}]}``),
      * a ``{"data": [...]}`` envelope whose items are name strings or ``{"name": ...}``.

    Raises ``ValueError`` for an unrecognised shape so a malformed snapshot fails loud
    rather than silently comparing against an empty set.
    """
    if isinstance(payload, dict):
        if "result" in payload and isinstance(payload["result"], dict):
            payload = payload["result"]
        if isinstance(payload, dict):
            for key in ("tools", "data"):
                if key in payload:
                    payload = payload[key]
                    break
    if not isinstance(payload, list):
        raise ValueError(
            "unrecognised catalog snapshot shape: expected a list of names, an MCP "
            "tools/list result, or a {'data': [...]} envelope"
        )
    names: list[str] = []
    for item in payload:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
        else:
            raise ValueError(f"catalog entry has no string name: {item!r}")
    return names


@dataclass(frozen=True)
class CatalogDiff:
    """Result of comparing the registered tool set against a deployed catalog.

    ``missing_from_catalog`` — registered here but absent from the catalog (unreachable
    regression). ``unexpected_in_catalog`` — present in the catalog for this gateway but
    not registered here (stale/phantom entry). ``is_clean`` is true iff both are empty.
    """

    missing_from_catalog: list[str] = field(default_factory=list)
    unexpected_in_catalog: list[str] = field(default_factory=list)
    registered: list[str] = field(default_factory=list)
    catalog: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.missing_from_catalog and not self.unexpected_in_catalog

    def summary(self) -> str:
        if self.is_clean:
            return (
                f"catalog in sync: {len(self.registered)} registered tools all present "
                "in the deployed catalog, no unexpected entries."
            )
        lines = [
            f"catalog DRIFT: {len(self.registered)} registered, "
            f"{len(self.catalog)} in catalog (this gateway)."
        ]
        if self.missing_from_catalog:
            lines.append(
                "  registered but MISSING from catalog (unreachable): "
                + ", ".join(self.missing_from_catalog)
            )
        if self.unexpected_in_catalog:
            lines.append(
                "  in catalog but NOT registered (stale/phantom): "
                + ", ".join(self.unexpected_in_catalog)
            )
        return "\n".join(lines)


def diff_catalog(
    registered: Iterable[str],
    catalog_names: Iterable[str],
    gateway_slug: str = DEFAULT_GATEWAY_SLUG,
) -> CatalogDiff:
    """Compare the registered tool set against a deployed catalog for one gateway."""
    registered_set = set(registered)
    catalog_set = catalog_base_names(catalog_names, gateway_slug)
    return CatalogDiff(
        missing_from_catalog=sorted(registered_set - catalog_set),
        unexpected_in_catalog=sorted(catalog_set - registered_set),
        registered=sorted(registered_set),
        catalog=sorted(catalog_set),
    )
