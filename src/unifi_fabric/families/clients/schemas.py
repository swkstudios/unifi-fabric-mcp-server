"""The clients family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

_CONSOLE_SITE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}"

#: Classic ``meta.msg`` codes that state the resource does not exist. Any other Classic
#: error (``api.err.NoPermission``, ``api.err.LoginRequired``, ``api.err.InvalidObject``,
#: ...) is not evidence of absence and propagates. An unknown ``rest/user/{id}`` is not one
#: of them: read live on Network 11.1.47 (2026-11-11, development console), a well-formed
#: unknown id and a non-id string both answered HTTP 200 ``{"meta": {"rc": "ok"}, "data": []}``,
#: never HTTP 400 ``api.err.InvalidObject``; the empty ``data`` is the absence (no row).
_CLASSIC_NOT_FOUND_MSGS = frozenset({"api.err.NotFound", "api.err.ClientNotFound"})

#: ``list_guests`` sources: Classic ``stat/guest`` (default) and the controller's v2 hotspot
#: client list (Network 11.0.81 web UI, GET /proxy/network/v2/api/site/{site}/hotspot/clients).
GUEST_SOURCES = ("classic", "v2")

_FIXED_IP_HINT = (
    "set_client_fixed_ip / create_client_reservation: the controller needs the network the "
    "address belongs to; pass network (name, _id or Integration id from list_networks) when "
    "the client record has no network_id yet, and an address inside that network's subnet."
)

_CLASSIC_CMD_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd"

#: Every connected-client type the published Network spec lists (Network 11.0.97
#: "Client overview" / "Client details" discriminator on ``type``; pinned to the vendored
#: spec by a test, so a type the spec adds fails until it is accepted here).
CLIENT_TYPES = ("WIRED", "WIRELESS", "VPN", "TELEPORT")

# The actions the published executeConnectedClientAction operation accepts (Network
# 11.0.97 "Client action request": a discriminator on ``action``). Block, unblock and
# reconnect are NOT among them: they are block_client / unblock_client / reconnect_client.
_CLIENT_ACTIONS = ("AUTHORIZE_GUEST_ACCESS", "UNAUTHORIZE_GUEST_ACCESS")
