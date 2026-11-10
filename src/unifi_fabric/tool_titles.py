"""Display titles for tools, with product names and acronyms spelled correctly.

MCP clients show a tool's ``title`` to people. Without one, FastMCP derives it from
the tool name with plain title-casing, which turns ``list_isp_metrics`` into
``List Isp Metrics`` and ``list_mc_lags`` into ``List Mc Lags``. This module derives
the same word-per-segment title but spells networking acronyms and product names
the way UniFi documentation does (``List ISP Metrics``, ``List MC-LAGs``).

The title is display metadata only: tool names, input schemas, annotations and
behaviour are unchanged. :func:`install_tool_titles` sets the title once, at one
shared point, on every registered tool.
"""

from __future__ import annotations

from typing import Any

#: Tool-name word -> display spelling. Words not listed are capitalised normally
#: (``arm`` is the Protect arm/disarm verb, not an acronym, so it stays ``Arm``).
ACRONYMS: dict[str, str] = {
    "acl": "ACL",
    "ap": "AP",
    "aps": "APs",
    "api": "API",
    "ddns": "DDNS",
    "dhcp": "DHCP",
    "dns": "DNS",
    "dpi": "DPI",
    "id": "ID",
    "ids": "IDs",
    "innerspace": "InnerSpace",
    "ip": "IP",
    "isp": "ISP",
    "lag": "LAG",
    "lags": "LAGs",
    "lan": "LAN",
    "nvr": "NVR",
    "poe": "PoE",
    "pos": "POS",
    "ptz": "PTZ",
    "radius": "RADIUS",
    "rtsps": "RTSPS",
    "sdwan": "SD-WAN",
    "ssid": "SSID",
    "stp": "STP",
    "ulp": "ULP",
    "unifi": "UniFi",
    "vlan": "VLAN",
    "vpn": "VPN",
    "wan": "WAN",
    "wifi": "WiFi",
    "wlan": "WLAN",
}

#: Two-word sequences that form one hyphenated term (``mc_lag`` -> ``MC-LAG``).
_COMPOUNDS: dict[tuple[str, str], str] = {
    ("mc", "lag"): "MC-LAG",
    ("mc", "lags"): "MC-LAGs",
}


def acronym_title(name: str) -> str:
    """Return the display title for tool ``name`` (``list_isp_metrics`` -> ``List ISP Metrics``)."""
    words = [w for w in name.replace("-", "_").split("_") if w]
    out: list[str] = []
    i = 0
    while i < len(words):
        word = words[i].lower()
        if i + 1 < len(words) and (word, words[i + 1].lower()) in _COMPOUNDS:
            out.append(_COMPOUNDS[(word, words[i + 1].lower())])
            i += 2
            continue
        out.append(ACRONYMS.get(word, word.capitalize()))
        i += 1
    return " ".join(out)


def install_tool_titles(mcp: Any) -> int:
    """Set an acronym-aware ``title`` on every registered tool that has none.

    A title set explicitly at registration (``@mcp.tool(title=...)``) is kept. Returns
    the number of tools titled. Only the ``title`` attribute is touched, so this
    coexists with the response-redaction wrapper (which replaces ``fn``), the
    argument-error middleware and the tool-family filter (which removes tools).
    """
    try:
        from .local_components import tool_components

        components = tool_components(mcp)
    except AttributeError:  # pragma: no cover - defensive against FastMCP internals
        return 0
    titled = 0
    for component in components:
        if not hasattr(component, "parameters") or getattr(component, "title", None):
            continue
        component.title = acronym_title(component.name)
        titled += 1
    return titled
