"""RADIUS profile update and delete on the Classic REST route the controller UI uses.

The published Integration API serves RADIUS profiles GET-only (list_radius_profiles); the
create tool lives with the other VPN/RADIUS tools in ``vpn.py``. These two writes share the
site configuration CRUD core (``site_config``) and belong to the ``vpn`` tool family.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ...tool_annotations import WRITE
from ..network.site_config import RADIUS_PROFILES, _delete_config_record, _update_config_record


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the RADIUS profile update and delete tools."""

    @mcp.tool(annotations=WRITE)
    async def update_radius_profile(
        host: str, site: str, profile_id: str, profile: dict[str, Any]
    ) -> Any:
        """Update a RADIUS profile via Classic REST PUT rest/radiusprofile/{_id}.

        The published Integration API serves RADIUS profiles GET-only; this is the UI's route.
        The id (list_radius_profiles id = external_id, or the Classic _id) is resolved in
        rest/radiusprofile first (an unknown id fails listing every profile, no write is
        sent). auth_servers / acct_servers replace the whole server list: send every server
        to keep, each {ip, port, x_secret}.

        Returns: the upstream body verbatim, {meta: {rc}, data: [the updated profile]}.
        Additive _warnings (NO_ID_RETURNED, NOT_STORED_AS_SENT: field names only) report a
        write that did not land as sent. Under dry-run policy nothing is sent: the bare dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Example call (update_radius_profile):
            {"host": "my-console", "site": "Default",
             "profile_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "profile": {"interim_update_enabled": true}}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile_id: RADIUS profile id from list_radius_profiles (data[].id) or its Classic
                _id.
            profile: Native radiusprofile fields to change. Free-form JSON object; no published
                body shape.
        """
        client, registry = deps_fn()
        return await _update_config_record(
            client, registry, host, site, RADIUS_PROFILES, profile_id, "profile_id", profile
        )

    @mcp.tool(annotations=WRITE)
    async def delete_radius_profile(host: str, site: str, profile_id: str) -> dict[str, Any]:
        """Delete a RADIUS profile via Classic REST DELETE rest/radiusprofile/{_id}.

        Consequence: WiFi networks and ports using the profile for 802.1X lose their RADIUS
        servers (the controller refuses while one still uses it, and its error is returned).
        There is no undo.

        The id (list_radius_profiles id = external_id, or the Classic _id) is resolved in
        rest/radiusprofile first, so an unknown id is never reported as deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body
        verbatim. Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false,
        message, response (the preview with method, path, params (query parameters), body)}.

        Example call (delete_radius_profile):
            {"host": "my-console", "site": "Default",
             "profile_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            profile_id: RADIUS profile id from list_radius_profiles (data[].id) or its Classic
                _id.
        """
        client, registry = deps_fn()
        return await _delete_config_record(
            client, registry, host, site, RADIUS_PROFILES, profile_id, "profile_id"
        )
