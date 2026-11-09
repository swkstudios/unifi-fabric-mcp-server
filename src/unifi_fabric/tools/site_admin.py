"""Network site administration tools: create, rename and delete sites of a console.

The Classic REST site manager (``/proxy/network/api/s/{site}/cmd/sitemgr``) carries the
commands the controller UI sends: ``add-site`` {desc}, ``update-site`` {desc} (renames
the site the URL addresses) and ``delete-site`` {site: <site _id>}. Sites are listed by
``/proxy/network/api/self/sites`` ({_id, name (the URL slug), desc (the display name)}).

Probed on Network 11.0.81 (a single-site UniFi OS gateway console): ``update-site`` with
the current name was accepted (rc ok, name unchanged); ``delete-site`` of an absent id
answered HTTP 400 ``api.err.IdInvalid`` (the command is reached); ``add-site`` answered
HTTP 400 ``api.err.NotImplemented``: that console has no multi-site support, so creating
and deleting a site work only on consoles that host several sites (UniFi OS Server, Cloud
Key) and stay hermetic-only, needing a live test there.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..client import UniFiClient, upstream_error_value, validate_selector
from ..config import APIKeyConfig
from ..matching import name_matches, same_id
from ..registry import Registry
from ..tool_annotations import WRITE
from ._classic_objects import _classic_data, listed_record_id, resolve_site_slug
from ._payload import with_upstream_hint
from ._results import deletion_result

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network/api"

_MULTI_SITE_HINT = (
    "Creating and deleting sites needs a console that hosts several Network sites (UniFi OS "
    "Server, Cloud Key); a UniFi OS gateway console answers api.err.NotImplemented to "
    "add-site."
)


def _sitemgr(host_id: str, site_slug: str) -> str:
    return _CONSOLE.format(host_id=host_id) + f"/s/{site_slug}/cmd/sitemgr"


async def _console_sites(
    client: UniFiClient, host_id: str, key: APIKeyConfig | None
) -> list[dict[str, Any]]:
    path = _CONSOLE.format(host_id=host_id) + "/self/sites"
    return _classic_data(await client.get(path, key=key), path)


def _describe_sites(sites: list[dict[str, Any]], client: UniFiClient | None = None) -> str:
    return (
        "; ".join(
            f"{upstream_error_value(s.get('desc'), client)!r} "
            f"(name={upstream_error_value(s.get('name'), client)}, "
            f"_id={upstream_error_value(s.get('_id'), client)})"
            for s in sites
        )
        or "(none)"
    )


def _select_site(
    sites: list[dict[str, Any]], wanted: str, arg: str, client: UniFiClient | None = None
) -> dict[str, Any]:
    """The site whose _id, name (slug) or desc (display name) is ``wanted``."""
    by_id = [s for s in sites if same_id(wanted, s.get("_id")) or s.get("name") == wanted]
    matches = by_id or name_matches(sites, wanted, lambda s: s.get("desc"))
    if len({id(s) for s in matches}) > 1:
        raise ValueError(
            f"{arg} {wanted!r} matches {len(matches)} sites: {_describe_sites(matches, client)}. "
            "Pass its _id."
        )
    if not matches:
        raise ValueError(
            f"{arg} {wanted!r} not found by _id, name or display name; sites: "
            f"{_describe_sites(sites, client)}. Get them from list_local_sites or list_sites."
        )
    listed_record_id(matches[0], arg)
    return matches[0]


async def _create_site(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    description: str,
) -> Any:
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await with_upstream_hint(
        client.post(
            _sitemgr(host_id, site_slug), key=key, json={"cmd": "add-site", "desc": description}
        ),
        _MULTI_SITE_HINT,
    )


async def _rename_site(
    client: UniFiClient, registry: Registry, host: str, site: str, description: str
) -> Any:
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.post(
        _sitemgr(host_id, site_slug), key=key, json={"cmd": "update-site", "desc": description}
    )


async def _delete_site(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    site_to_delete: str,
) -> dict[str, Any]:
    validate_selector(site_to_delete, "site_to_delete")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    sites = await _console_sites(client, host_id, key)
    target = _select_site(sites, site_to_delete, "site_to_delete", client)
    target_id = listed_record_id(target, "site_to_delete")
    response = await with_upstream_hint(
        client.post(
            _sitemgr(host_id, site_slug), key=key, json={"cmd": "delete-site", "site": target_id}
        ),
        _MULTI_SITE_HINT,
    )
    return deletion_result(f"Site {target.get('desc')!r} (_id {target_id}) deleted.", response)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the site administration MCP tools."""

    @mcp.tool(annotations=WRITE)
    async def create_site(
        host: str,
        site: str,
        description: str,
    ) -> Any:
        """Create a new Network site on a console that hosts several sites.

        Classic REST POST network/api/s/{site}/cmd/sitemgr with {"cmd": "add-site", "desc":
        description} (the controller UI's request; no published spec): the command is sent
        through an existing site of the console (e.g. "Default"). A UniFi OS
        gateway console has no multi-site support and answers HTTP 400 api.err.NotImplemented
        (Network 11.0.81); multi-site consoles (UniFi OS Server, Cloud Key) create the site.
        Not yet live-tested on a multi-site console.

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [the new site {_id,
        name (its URL slug), desc}]} (under dry-run policy, the dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params (query
        parameters), body}} instead).

        Example call (create_site):
            {
              "host": "my-console",
              "site": "Default",
              "description": "Branch office"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: An existing Network site to send the command through (name or UUID, resolved
                server-side), e.g. "Default". Get it from list_local_sites (name or id).
            description: Display name of the new site, e.g. "Branch office".
        """
        client, registry = deps_fn()
        return await _create_site(client, registry, host, site, description)

    @mcp.tool(annotations=WRITE)
    async def rename_site(
        host: str,
        site: str,
        description: str,
    ) -> Any:
        """Rename a Network site (change its display name).

        Consequence: tools and clients that select the site by its old display name must use
        the new one; the site's id and URL slug do not change.

        Classic REST POST network/api/s/{site}/cmd/sitemgr with {"cmd": "update-site", "desc":
        description} (the controller UI's request; no published spec): it renames the site the
        URL addresses. Verified on Network 11.0.81 with the current name (accepted, rc ok).

        Returns the upstream Classic body verbatim: {meta: {rc}, data: [...]} (under
        dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead). Read
        list_local_sites afterwards to see the new name.

        Example call (rename_site):
            {
              "host": "my-console",
              "site": "Default",
              "description": "Head office"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            description: The new display name, e.g. "Head office".
        """
        client, registry = deps_fn()
        return await _rename_site(client, registry, host, site, description)

    @mcp.tool(annotations=WRITE)
    async def delete_site(
        host: str,
        site: str,
        site_to_delete: str,
    ) -> dict[str, Any]:
        """Delete a Network site and everything configured in it.

        Consequence: the site and the configuration stored in it (networks, WiFi, firewall
        rules, client records, device settings) are removed; move its devices to another site
        first. There is no undo.

        The site to delete is resolved in the console's site list (network/api/self/sites) by
        _id, URL name or display name; an unknown or ambiguous value fails listing the sites and
        nothing is sent. Then Classic REST POST network/api/s/{site}/cmd/sitemgr with {"cmd":
        "delete-site", "site": SITE_ID} (the controller UI's request; no published spec), sent
        through another existing site (e.g. "Default"). The controller judges what may be
        deleted (the default site cannot be). A UniFi OS gateway console has a single site and
        nothing to delete; not yet live-tested on a multi-site console.

        Returns {deleted: true, message, response}; response is the upstream body verbatim.
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params (query parameters), body}})}.

        Example call (delete_site):
            {
              "host": "my-console",
              "site": "Default",
              "site_to_delete": "Branch office"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Another existing Network site to send the command through (name or UUID,
                resolved server-side), e.g. "Default". Get it from list_local_sites (name or id).
            site_to_delete: The site to delete: its _id, URL name or display name, from
                list_local_sites or list_sites, e.g. "Branch office".
        """
        client, registry = deps_fn()
        return await _delete_site(client, registry, host, site, site_to_delete)
