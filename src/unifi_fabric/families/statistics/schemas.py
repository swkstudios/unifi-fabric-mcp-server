"""The statistics family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

from typing import Literal

Product = Literal["network", "protect"]

_PUSH_NOTE = (
    "Reading a buffer never subscribes the MCP client to notifications; this server sends "
    "no MCP push notifications for events."
)

_MODERN_STATS_BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/stats"

# /stat/report path is "{interval}.{scope}", e.g. "hourly.ap". Every interval and scope
# the controller accepts, from live read-only probes of each candidate on Network 11.0.81:
# each value here answered 200 rc "ok" in every interval x scope pair; every other candidate was
# refused (an unknown interval with HTTP 400 api.err.InvalidArgs, an unknown scope with an
# HTTP 500 HTML page), so it is rejected here with this full list instead.
REPORT_INTERVALS = ("minute", "5minutes", "hourly", "daily", "monthly", "archive")
REPORT_SCOPES = ("site", "ap", "user", "gw", "sw", "device", "speedtest", "isp")

#: The session classes of Classic ``stat/session`` ``type``, as UniFi documents them.
SESSION_TYPES = ("all", "user", "guest", "voucher")

#: ``list_known_clients`` sources: Classic ``/stat/alluser`` (default) and the controller's
#: v2 client history (Network 11.0.81 web UI, GET
#: /proxy/network/v2/api/site/{site}/clients/history).
KNOWN_CLIENTS_SOURCES = ("classic", "v2")

# Device-level thermal/power summary keys surfaced by the device view of
# get_device_port_state. Values are copied verbatim under their upstream names.
_DEVICE_THERMAL_POWER_KEYS = (
    "general_temperature",
    "fan_level",
    "overheating",
    "total_used_power",
    "total_max_power",
)

# Device- and port-level STP keys surfaced by get_device_stp_state. Any additional ``stp_*``
# key present upstream is also carried through, so these are a floor, not a whitelist that
# could silently drop a future field.
_DEVICE_STP_KEYS = ("stp_version", "stp_priority", "root_switch", "root")
_PORT_STP_KEYS = ("stp_state", "stp_role", "stp_pathcost", "stp_path_cost")

#: Page size of a default drain (a caller page_size requests a total). Network 11.0.81
#: served pages of 1,000 and 5,000 entries; the default page is 50, so a full drain
#: of a busy log would otherwise take hundreds of requests.
DRAIN_PAGE_SIZE = 1000

#: The entry kinds the controller UI names for each class whose query needs them (the
#: Art-of-WiFi UniFi API client's get_system_log carries the same lists). Sent only when
#: the caller's query does not already set that key.
CLASS_DEFAULTS: dict[str, dict[str, list[str]]] = {
    "next-ai-alert": {"nextAiCategory": ["CLIENT", "DEVICE", "INTERNET", "VPN"]},
    "admin-activity": {
        "activity_keys": [
            "ACCESSED_NETWORK_WEB",
            "ACCESSED_NETWORK_IOS",
            "ACCESSED_NETWORK_ANDROID",
        ],
        "change_keys": [
            "CLIENT",
            "DEVICE",
            "HOTSPOT",
            "INTERNET",
            "NETWORK",
            "PROFILE",
            "ROUTING",
            "SECURITY",
            "SYSTEM",
            "VPN",
            "WIFI",
        ],
    },
    "update-alert": {
        "systemLogDeviceTypes": [
            "GATEWAYS",
            "SWITCHES",
            "ACCESS_POINT",
            "SMART_POWER",
            "BUILDING_TO_BUILDING_BRIDGES",
            "UNIFI_LTE",
        ]
    },
    "client-alert": {
        "clientType": ["GUEST", "TELEPORT", "VPN", "WIRELESS", "RADIUS", "WIRED"],
        "guestAuthorizationMethod": [
            "FACEBOOK_SOCIAL_GATEWAY",
            "FREE_TRIAL",
            "GOOGLE_SOCIAL_GATEWAY",
            "NONE",
            "PASSWORD",
            "PAYMENT",
            "RADIUS",
            "VOUCHER",
        ],
    },
    "threat-alert": {"threatTypes": ["HONEYPOT", "THREAT"]},
    "triggers": {"triggerTypes": ["TRAFFIC_RULE", "TRAFFIC_ROUTE", "FIREWALL_RULE"]},
}

#: The classes seen answering on Network 11.0.81 (``triggers`` answered 404 there), for
#: descriptions only. This is not a classifier or allowlist: every system-log POST is
#: a write, including these classes and any other class sent for the controller to judge.
KNOWN_CLASSES = (
    "all",
    "device-alert",
    "client-alert",
    "admin-activity",
    "update-alert",
    "threat-alert",
    "next-ai-alert",
    "vpn-alert",
    "critical",
    "triggers",
)

#: The GET routes ``system-log/{scope}/{identifier}`` of the Network 11.0.81 frontend bundle
#: (``tests/fixtures/private_api/inventory_network_11.0.81.json``). ``device`` and
#: ``client-connection`` answered HTTP 200 on a live console (probed 2026-10-17, ``device``
#: with a list of events; ``client-connection`` with an empty list, shape unproven);
#: ``admin-activity`` and ``by-external-id`` answered HTTP 404 for an id the console did not
#: hold (no admin record and no external-id match existed to ask for), so their positive shape
#: is unproven. This is a route selector, not a classifier: every route is a plain GET.
SCOPED_LOG_ROUTES: dict[str, str] = {
    "device": "a device MAC address",
    "client-connection": "a client MAC address",
    "admin-activity": "an admin-activity record id",
    "by-external-id": "an external id",
}

#: The nine class routes on the read-POST allowlist, as the ``log_class`` enum of get_system_log.
SystemLogClass = Literal[
    "all",
    "device-alert",
    "client-alert",
    "admin-activity",
    "update-alert",
    "threat-alert",
    "next-ai-alert",
    "vpn-alert",
    "critical",
]

#: The system-log class an evidence collection reads when the caller names none.
EVIDENCE_DEFAULT_CLASSES = ("all",)

#: The system-log classes the readers may send: exactly the routes on the read-POST allowlist
#: (``read_post_routes``). Another class stays a write; adding one is its own allowlist entry
#: with its own proof.
EVIDENCE_READ_CLASSES = (
    "all",
    "device-alert",
    "client-alert",
    "admin-activity",
    "update-alert",
    "threat-alert",
    "next-ai-alert",
    "vpn-alert",
    "critical",
)
