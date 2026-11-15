"""The hotspot family registrar: its tool wrappers, in registration order (the family-owned layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ...tool_annotations import READ_ONLY, WRITE
from . import hotspot


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all hotspot MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_hotspot_operators(
        host: str,
        site: str,
    ) -> Any:
        """List hotspot operator accounts for captive portal management.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [operator…]}
        verbatim. To change one, edit its data[] entry and pass it as `fields` to
        update_hotspot_operator (operator_id = its _id).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await hotspot._list_hotspot_operators(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_hotspot_operator(
        host: str,
        site: str,
        name: str,
        password: str,
        note: str | None = None,
    ) -> Any:
        """Create a hotspot operator account.

        Request body: no published schema exists for POST network/api/s/{site}/rest/hotspotop
        (classic); the tool builds {name, x_password} plus note when you pass one.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [operator]}
        verbatim; the new operator's _id is data[0]._id. Under dry-run policy nothing is sent:
        {status: "dry_run", response (the preview)}.

        Example call (create_hotspot_operator):
            {
              "host": "my-console",
              "site": "Default",
              "name": "frontdesk",
              "password": "change-me-123"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            name: Hotspot operator username (classic REST hotspotop.name).
            password: Operator password (sent as x_password).
            note: Optional free-text note.
        """
        client, registry = deps_fn()
        return await hotspot._create_hotspot_operator(
            client,
            registry,
            host,
            site,
            name,
            password,
            note=note,
        )

    @mcp.tool(annotations=WRITE)
    async def update_hotspot_operator(
        host: str,
        site: str,
        operator_id: str,
        fields: dict[str, Any],
    ) -> Any:
        """Update a hotspot operator by ID.

        The id is resolved in list_hotspot_operators first: an unknown id fails listing every valid
        _id, and nothing is written.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/hotspotop/{id}
        (classic controller API). Pass the controller's native payload; read the current object
        first with list_hotspot_operators and send back the edited data[] entry. Empty strings
        inside list-valued fields are dropped before the write.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [operator]} verbatim.
        Under dry-run policy nothing is sent: {status: "dry_run", response (the preview)}.

        Example call (update_hotspot_operator):
            {
              "host": "my-console",
              "site": "Default",
              "operator_id": "000000000000000000000107",
              "fields": {"note": "Night shift"}
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            operator_id: Hotspot operator _id (classic REST hotspotop). Get it from
                list_hotspot_operators (_id).
            fields: spec: free-form (classic REST hotspotop). Fields to change: name, x_password,
                note.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await hotspot._update_hotspot_operator(
            client, registry, host, site, operator_id, fields
        )

    @mcp.tool(annotations=WRITE)
    async def delete_hotspot_operator(
        host: str,
        site: str,
        operator_id: str,
    ) -> dict[str, Any]:
        """Delete a hotspot operator by ID.

        Consequence: the operator account can no longer sign in; there is no undo.

        The id is resolved in list_hotspot_operators first (the controller answers a DELETE on an unknown id with HTTP 200): an unknown id fails listing every valid _id and nothing is deleted. Under dry-run policy nothing is deleted; returns {status: "dry_run", deleted: false, message, response (the preview)}. The dry-run preview contains method, path, params (query parameters), and body.

        Example call (delete_hotspot_operator):
            {"host": "my-console", "site": "Default", "operator_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            operator_id: Hotspot operator _id (classic REST hotspotop). Get it from
                list_hotspot_operators (_id).
        """
        client, registry = deps_fn()
        return await hotspot._delete_hotspot_operator(client, registry, host, site, operator_id)
