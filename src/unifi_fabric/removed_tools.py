"""Tools this release removed, and what to call instead (its migration guide's table).

A call naming one of them gets a coded ``tool_removed`` error that names the replacement,
instead of a bare unknown-tool error. No request is sent.
"""

from __future__ import annotations

import json

from fastmcp.exceptions import ToolError

TOOL_REMOVED = "tool_removed"

_NO_QR = "Protect 7.3.74 has no QR route"
_NO_ROUTE = "Protect 7.3.74 has no matching route"
_NO_TRAFFIC = "the console does not implement {} traffic rules"

#: removed tool name -> the guidance returned with the error.
REMOVED_TOOLS: dict[str, str] = {
    "get_camera_adoption_qr": f"it has no replacement; {_NO_QR}",
    "calibrate_door_lock": f"it has no replacement; {_NO_ROUTE}",
    "set_door_lock_auto_close": f"it has no replacement; {_NO_ROUTE}",
    "get_protect_case_asset_snapshot": (
        "use list_protect_case_assets, then get_thumbnail with the asset's snapshot "
        "thumbnail id (snapshot on a presentation asset, thumbnail on a clip)"
    ),
    "reboot_nvr": "use reboot_unifi_os_console",
    "update_protect_user_notifications": (
        "it has no direct replacement; set_protect_notification_receivers and "
        "set_protect_notifications_muted cover notification receivers and muting"
    ),
    "create_traffic_rule": (
        "use create_firewall_policy, create_qos_rule or create_traffic_route, depending on "
        "whether the rule blocks or allows, limits rate or sends traffic through a WAN or VPN"
    ),
    "update_traffic_rule": f"it has no replacement; {_NO_TRAFFIC.format('changing')}",
    "delete_traffic_rule": f"it has no replacement; {_NO_TRAFFIC.format('deleting')}",
}


def _migration_guide() -> str:
    """The installed release's migration guide, read from the package version at call time."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"docs/MIGRATING-{version('unifi-fabric-mcp-server')}.md"
    except PackageNotFoundError:
        return "the release's migration guide (docs/MIGRATING-<version>.md)"


def removed_tool_error(name: str) -> ToolError | None:
    """The coded error for a call to a removed tool, or ``None`` for any other name."""
    guidance = REMOVED_TOOLS.get(name)
    if guidance is None:
        return None
    message = (
        f"{name!r} was removed in this release: {guidance}. No request was sent. "
        f"See {_migration_guide()}."
    )
    return ToolError(json.dumps({"error": {"code": TOOL_REMOVED, "message": message}}))
