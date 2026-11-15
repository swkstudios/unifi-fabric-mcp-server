"""The network family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

from typing import Literal

BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/site/{site_slug}"

#: The Integration error code a Network 11.0.89 controller answers (HTTP 400) when an access
#: point already carries its maximum number of SSIDs (live 2026-10-28). Network 11.0.97 gave
#: the same answer to an SSID created with enabled false (live 2026-11-08).
_WIFI_BROADCAST_LIMIT = "too-many-wifi-broadcasts"
_WIFI_BROADCAST_LIMIT_HINT = (
    "the controller limits how many SSIDs one access point broadcasts, and creating the SSID "
    "disabled (enabled: false) does not avoid the limit. With broadcastingDeviceFilter null "
    "the new SSID goes to every access point; scope it with broadcastingDeviceFilter "
    "({type: DEVICES or DEVICE_TAGS, ...}) to access points that have a free slot, or remove "
    "an SSID from the full one (the device id in the message above) first."
)

_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"

#: Client observability views (``/v2/api/site/{site}/observability/client/{mac}/...``).
ObservabilityView = Literal["logs-all", "timeline", "timestamps", "topology"]
IconTarget = Literal["client", "matter_node"]
WifiReportTarget = Literal["client", "ap"]
GuestTarget = Literal["client", "guest_session"]

CLOUD_ACCESS_ACTIONS = ("register", "unregister")
FIRMWARE_CACHE_ACTIONS = ("download", "remove")

ParamValue = str | int | float | bool

#: Appended after the verbatim upstream error of ``reboot_unifi_os_console``: the route the tool
#: posts to is the Network application's, which has no console reboot (the generic API-key hint
#: of a 401 would mislead).
REBOOT_ROUTE_HINT = (
    "reboot_unifi_os_console posts to the Network application "
    "(/proxy/network/api/system/reboot), which has no console reboot route (checked in "
    "Network 11.0.99). UniFi OS serves the reboot at the console root, POST /api/system/reboot, "
    "and the Fabric connector does not relay the console root. A 401 or 403 here comes from "
    "that route, not from the API key. This tool cannot reboot a console through this server; "
    "reboot it from the UniFi OS interface"
)

#: Configuration-defaults kinds: kind -> (scope, v2 route). ``site`` kinds are
#: ``/v2/api/site/{site}/<route>``; ``console`` kinds are ``/v2/api/<route>``.
DEFAULTS_ROUTES: dict[str, tuple[str, str]] = {
    "port_profile": ("site", "/port-profiles/defaults"),
    "wan": ("site", "/wan/defaults"),
    "lan": ("site", "/lan/defaults"),
    "wlan": ("site", "/wlan/defaults"),
    "firewall_policy": ("site", "/firewall-policies/defaults"),
    "firewall_zone": ("site", "/firewall/zone/defaults"),
    "connectivity": ("site", "/settings/connectivity/defaults"),
    "doh": ("site", "/settings/doh/defaults"),
    "element_adopt": ("site", "/settings/element_adopt/defaults"),
    "global_switch": ("site", "/settings/global_switch/defaults"),
    "ips_advanced_filtering": ("site", "/settings/ips/advanced-filtering-defaults"),
    "netflow": ("site", "/settings/netflow/defaults"),
    "ntp": ("site", "/settings/ntp/defaults"),
    "usg": ("site", "/settings/usg/defaults"),
    "wifiai": ("site", "/settings/wifiai/defaults"),
    "ssl_inspection_profile": ("site", "/ssl-inspection/profiles/defaults"),
    "ssl_inspection_setting": ("site", "/ssl-inspection/setting/defaults"),
    "system_log_setting": ("site", "/system-log/setting/defaults"),
    "log_levels": ("console", "/log-levels/defaults"),
    "super_mgmt": ("console", "/settings/super-mgmt/defaults"),
}

DefaultsKind = Literal[
    "port_profile",
    "wan",
    "lan",
    "wlan",
    "firewall_policy",
    "firewall_zone",
    "connectivity",
    "doh",
    "element_adopt",
    "global_switch",
    "ips_advanced_filtering",
    "netflow",
    "ntp",
    "usg",
    "wifiai",
    "ssl_inspection_profile",
    "ssl_inspection_setting",
    "system_log_setting",
    "log_levels",
    "super_mgmt",
]

#: Statistics views and the v2 route each reads (``/v2/api/<route>``).
STATS_ROUTES: dict[str, str] = {
    "recent_series": "/stats/recent/series",
    "series": "/stats/series",
    "source": "/stats/source",
}
StatsView = Literal["recent_series", "series", "source"]

UpsAction = Literal["pair", "unpair"]
WarningsSource = Literal["all", "network", "controller"]

STAT_SCHEMA_SITE_DPI = "applicationTrafficBySite"
STAT_SCHEMA_CLIENT_DPI = "applicationTrafficBySiteByClient"

_HOST = (
    'Console name or composite id from list_hosts; for example "Home UDM" (hostname or '
    "reportedState.name, case-insensitive)."
)
_SITE = 'Network site name or id from list_local_sites; for example "Default".'

#: SSH session actions and the Classic ``cmd/devmgr`` command each sends.
SSH_COMMANDS: dict[str, str] = {
    "build": "build-ssh-session",
    "sdp_answer": "ssh-sdp-answer",
    "close": "close-ssh-session",
}

_FE = "Network 11.0.81 front-end bundle"

#: The preview route's version facts. The 405 error text reads these; the tool docstring states
#: the same two versions literally (a result statement must be the tool's own source text), and
#: tests/test_network_dpi_policy.py fails if either drifts from these constants.
PREVIEW_RULE_405_VERSION = "11.0.89"
PREVIEW_RULE_MIN_VERSION = "11.1.11"

#: The Integration error code a Network 11.0.89 controller answers (HTTP 400) to a PUT on a
#: policy whose ``metadata.origin`` is ``SYSTEM_DEFINED`` (live 2026-10-28, a "Block Invalid
#: Traffic" policy with ``metadata.configurable`` true).
_SYSTEM_DEFINED_POLICY_REFUSAL = "system-defined-firewall-policy-update-forbidden"
_SYSTEM_DEFINED_POLICY_HINT = (
    "this PUT replaces a whole policy and the controller refuses it for a SYSTEM_DEFINED "
    "policy (metadata.origin). The published Integration API patches only loggingEnabled and "
    "reportFlowEnabled on such a policy: use patch_firewall_policy with "
    "{loggingEnabled|reportFlowEnabled: true|false}. A "
    "USER_DEFINED policy takes this full update."
)

LteManager = Literal["lte", "mbb"]
EsimAction = Literal["add", "delete"]
LoadBalancingView = Literal["configuration", "status"]

EnrichedKind = Literal["wan", "lan", "wlan"]

_INSIGHT_ROUTES: dict[str, str] = {
    "overview": "overview",
    "history": "history",
    "speed_tests": "speed-tests",
}

_NAT = "/nat"
_QOS = "/qos-rules"
_CONTENT_FILTERS = "/content-filtering"
_FLOWS = "/traffic-flows"
#: The largest traffic-flow ``pageSize`` the console accepts. Measured live 2026-10-26 on
#: a development controller (read-POST evidence record 2026-10-26-flows-cap, cited by the
#: network-v2-traffic-flows entry of ``read_post_routes.READ_POST_ROUTES``): pageSize 5000
#: answered HTTP 200 and pageSize 10000 answered HTTP 400. A caller pageSize above it is
#: sent as this size until the requested total is gathered (:func:`_flow_page_batch`); a size at or
#: below it is sent unchanged and any upstream error for it is passed through verbatim.
TRAFFIC_FLOWS_MAX_PAGE_SIZE = 5000
_TOPOLOGY_VIEWS = ("live", "timeline", "timestamps", "at")

PROAV_KINDS = ("audio", "video")
SHADOW_VIEWS = {"info": "/shadowmode/info", "managed_group": "/shadowmode/managed/group"}
SHADOW_ACTIONS = {
    "begin": "/shadowmode/managed/begin-adoption",
    "complete": "/shadowmode/managed/complete-adoption",
    "rollback": "/shadowmode/managed/rollback",
}
TV_WALL_ACTIONS = {
    "set": "/proav/video/set-tv-wall-calibration",
    "unset": "/proav/video/unset-tv-wall-calibration",
}
TEST_CONFIG_ACTIONS = ("apply", "commit")
MULTICAST_VIEWS = ("client", "clients", "history")
_TEST_CONFIGS = "/test-configs"
_LAYOUT = "/digital-twin/layout"

#: Epoch values below this are almost certainly seconds passed by mistake. Not a spec
#: limit: a unit hint only; the value is always sent as given.
_SECONDS_HINT_BELOW = 100_000_000_000

#: Appended to an HTTP 404 from the 5G topology route. The Network 11.0.89 web app builds
#: the same route (``observability/5g/:mac:/topology/at/:timestamp:``) and reads it only
#: when the site's internet connection is a 5G device. Live evidence for the two wordings:
#: on 11.0.89 (2026-10-28) an adopted U5G Max in failover mode with no SIM answered the
#: bare HTML 404 the console gives an unserved path, and on 11.1.47 (2026-11-10) the
#: console's own MAC, which is not a 5G device, answered JSON ``api.err.DeviceNotFound``.
_5G_TOPOLOGY_NOT_SERVED = (
    "a 404 here means the console served no 5G topology for this MAC and time. Network "
    "11.1.47 answers JSON api.err.DeviceNotFound when the MAC is not a 5G device; Network "
    "11.0.89 answered its HTML 404 page even for an adopted U5G Max in failover mode with "
    "no SIM. Pass the MAC of a 5G device (list_devices, type umbb) with an epoch-milliseconds "
    "time; if list_devices shows no umbb device, the site has no 5G and the console serves "
    "no topology."
)

#: Appended to an HTTP 404 from a multicast-insights route. The routes exist in the pinned
#: Network 11.0.81 and 11.0.99 route tables; live on Network 11.1.47 (an early-access build)
#: the bare Tomcat HTML 404 an unserved path gets came back for the clients view.
_MULTICAST_NOT_SERVED = (
    "an HTML 404 here means this console's Network application does not serve multicast "
    "insights on this route: Network 11.0.81-11.0.99 serve it and the 11.1.47 web app no "
    "longer calls it. Check the version with get_network_application_info; there is no "
    "other route for this data."
)

_BGP = "/bgp/config"
_BGP_ALL = "/bgp/config/all"
_OSPF = "/ospf/router"
_GLOBAL = "/global/config/network"
_MCLAG = "/mclag-groups"
_STACK = "/stacking"
_VNET = "/visual-programming/virtual-network"
_STATUS_VIEWS = ("config", "neighbors")

#: list_ssl_inspection_catalog: catalog name -> v2 route suffix (route inventory GETs).
SSL_CATALOGS: dict[str, str] = {
    "categories": "/ssl-inspection/categories",
    "file-extensions": "/ssl-inspection/file-extensions",
    "search-engines": "/ssl-inspection/search-engines",
    "profile-defaults": "/ssl-inspection/profiles/defaults",
    "profile-usage": "/ssl-inspection/profiles/usage",
    "setting-defaults": "/ssl-inspection/setting/defaults",
}

_CERTS = "/ssl-inspection/certificates"
_PROFILES = "/ssl-inspection/profiles"
_SSL_SETTING = "/ssl-inspection/setting"
_LOG_SETTING = "/system-log/setting"

#: Epoch-millisecond fields of the Thread network and border-router records.
_THREAD_EPOCH_FIELDS = ("first_seen_at", "last_fresh_at", "last_seen_at")

#: The record keys an SSL inspection object may be addressed by (v2 ``_id``, else ``id``).
_ID_FIELDS = ("_id", "id")

_VERTEX_ID_FIELDS = ("client_id", "id", "_id", "node_id", "mac")

# Traffic Rules v2: /proxy/network/v2/api/site/{site_slug}/trafficrules
_V2_API_BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/site/{site_slug}"

# Fields managed by the UniFi controller that may change on every write
# regardless of whether the submitted payload was accepted.  Exclude these
# from silent-no-op comparison so that timestamp churn does not mask a
# genuinely rejected setting update.
_SERVER_MANAGED_FIELDS = frozenset(
    {
        "_id",
        "site_id",
        "key",
        "last_modified",
        "_updatedAt",
        "_createdAt",
    }
)

_NETWORKCONF_LIST_ID_FIELDS = ("excluded_networkconf_ids",)
_NETWORKCONF_SINGLE_ID_FIELDS = ("native_networkconf_id", "voice_networkconf_id")

#: Additive key carrying the id -> {id, name, vlan} resolution for a port profile. It is
#: added NEXT TO the controller's fields (which stay byte-identical, bare ids included)
#: and is stripped from any update_port_profile payload before the write.
RESOLVED_NETWORKS_KEY = "_resolved_networks"

RESOLVED_NETWORKS_ERROR_KEY = "_resolvedNetworksError"

_ENERGY = "/energy-saving-policies"
_PORT_AUTOMATIONS = "/port-automations"
_SUPERVISORS = "/power-supervisors"
_LINKS = "/power-supervisors/links"

_MULTI_SITE_HINT = (
    "Creating and deleting sites needs a console that hosts several Network sites (UniFi OS "
    "Server, Cloud Key); a UniFi OS gateway console answers api.err.NotImplemented to "
    "add-site."
)
