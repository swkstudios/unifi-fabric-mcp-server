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

from typing import Any

from ...client import UniFiClient, upstream_error_value, validate_selector
from ...config import APIKeyConfig
from ...matching import name_matches, same_id
from ...registry import Registry
from ...shared_shapes._classic_objects import _classic_data, listed_record_id, resolve_site_slug
from ...shared_shapes._payload import with_upstream_hint
from ...shared_shapes._results import deletion_result
from .schemas import (  # the family's shapes (family-owned layout)
    _MULTI_SITE_HINT,
)

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network/api"


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
