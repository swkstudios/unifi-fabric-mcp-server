"""The vpn family's v2 site-record helpers: site resolution, v2 reads, leaf updates.

Used by two vpn modules (the DNS handlers and the VPN tools) and by no other family, so
they are a private module of the family, not the common package. Moved verbatim from
``network_vpn_dns.py``, which imports them under their former names.
"""

from __future__ import annotations

from typing import Any

from ...client import UniFiClient
from ...config import APIKeyConfig
from ...redaction import drop_and_note_masked_fields
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import with_read_after_error
from ...write_body import IDENTITY_FIELDS, require_update_fields


def update_leaves(value: Any, what: str) -> dict[str, Any]:
    """The requested update leaves (masked and identity fields dropped), or raise."""
    clean = require_update_fields(drop_and_note_masked_fields(value), what)
    return {key: item for key, item in clean.items() if key not in IDENTITY_FIELDS}


def merge_leaves(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Recursively lay only the requested leaves over the current upstream record."""
    merged = dict(current)
    for key, value in changes.items():
        prior = merged.get(key)
        merged[key] = (
            merge_leaves(prior, value)
            if isinstance(prior, dict) and isinstance(value, dict)
            else value
        )
    return merged


def with_verdict(response: Any, after: Any, verified: bool | None, error: str | None) -> Any:
    """The write response verbatim plus ``_verified`` / ``_readAfter`` (additive keys).

    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    if not isinstance(response, dict):
        response = {"response": response}
    result = with_context(response, {"_verified": verified, "_readAfter": after})
    return with_read_after_error(result, error, additive=True)


async def site_slug(
    registry: Registry, host: str, site: str
) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


async def v2_get(client: UniFiClient, registry: Registry, host: str, site: str, route: str) -> Any:
    key, host_id, slug = await site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, route), key=key)
