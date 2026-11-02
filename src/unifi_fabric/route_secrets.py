"""Route-aware secret-field registry: one table for typed tools and the generic relay.

Some upstream routes carry a credential in a request body (a WireGuard private key, a
Protect device password, a Matter setup code) or hand one back (TURN credentials, an
OpenVPN client configuration, a teleport token, a stream URL token). This module is the
ONE place that lists them, keyed by route + method, so every consumer agrees:

* **Listing, not default masking.** An entry says which JSON keys (at any depth) and
  response headers hold a credential on that route. Tool output, dry-run previews and
  relayed bodies are masked ONLY when the operator opts in with ``UNIFI_REDACT_SECRETS``
  (default pass-through, R15-POLICY): :func:`mask_request_body` and
  :func:`mask_response_body` take that switch as an explicit argument and return the body
  unchanged when it is off. Nothing here masks by default.
* **Log, audit and error scrubbing** (a bound value never appears in a log or audit
  line; errors and failed results are masked of it only under ``UNIFI_REDACT_SECRETS``)
  uses :func:`request_secrets` / :func:`response_secrets` /
  :func:`tool_call_secrets` to extract the values, which the client chokepoint and the
  server's scrub middleware bind into the call's scrub scope (wired together with the
  Matter commissioning and camera share-link tools). A successful (2xx) upstream body is
  never altered by scrubbing.

``tests/test_route_secrets.py`` iterates :data:`ROUTE_SECRETS`, proves every entry matches
its own relay path and console path, extracts and masks synthetic sentinels only under the
opt-in, and leaves every other route untouched, so a new entry is covered automatically.

Each entry records its ``evidence``. ``verified=False`` marks key names inferred from the
route's purpose rather than read from a captured body: the change that adds the route's
tool confirms the key names (key names only, never values) and flips the flag.
Every entry, confirmed or inferred, binds its values into the call's error/log scrub
scope (:func:`bind_request`, :func:`bind_response`, :func:`tool_call_secrets`): an
inferred key name can only add scrubbing to free text, never remove it. A whole-body
credential (``response_body``) binds only for a 2xx response: an error page is
diagnostic text, scrubbed of the individually bound values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import SecretStr

from .redaction import REDACTION_MASK
from .secret_scrub import add_call_secrets, add_log_secrets

#: Every method a route entry may name.
ALL_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

#: The mask written in place of a listed value when ``UNIFI_REDACT_SECRETS`` is on: the
#: same mask the server's credential redaction uses.
MASK = REDACTION_MASK

#: The connector relay prefix every typed tool's console path carries before the
#: application route (``/v1/connector/consoles/<id>/proxy/``).
_PROXY_MARK = "/proxy/"


@dataclass(frozen=True)
class RouteSecret:
    """One route that carries a caller or upstream credential.

    Attributes:
        name: Stable id of the entry (test ids, docs).
        route: Regular expression full-matched against the application route: the part
            after ``/proxy/`` of a console path, or the relay's ``path`` argument, without
            leading/trailing slashes or a query string. An id or site segment is a
            single-segment wildcard (``[^/]+``), so the relay's ``{site}`` placeholder
            matches too.
        methods: HTTP methods the entry applies to.
        request_fields: JSON body keys whose values are credentials in a request.
        request_path_groups: Named regex groups holding credential path segments.
        response_fields: JSON body keys whose values are credentials in a response.
        response_log_fields: Values scrubbed from logs only; always returned to callers.
        response_headers: Response header names (case-insensitive) holding credentials.
        response_body: True when the whole non-JSON response body is the credential
            (a configuration file returned as text).
        tool_arguments: Typed tool name -> argument names holding the same credential.
        relay_path: The route as a relay caller writes it (``{site}`` and a synthetic
            id), used by the registry property test.
        evidence: Where the route and key names come from.
        verified: True when the key names were read from a captured request or response
            (key names only); False when inferred and still to be confirmed.
    """

    name: str
    route: str
    methods: frozenset[str]
    request_fields: tuple[str, ...] = ()
    request_path_groups: tuple[str, ...] = ()
    response_fields: tuple[str, ...] = ()
    response_log_fields: tuple[str, ...] = ()
    response_headers: tuple[str, ...] = ()
    response_body: bool = False
    tool_arguments: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    relay_path: str = ""
    evidence: str = ""
    verified: bool = False
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_pattern", re.compile(self.route))

    def matches(self, method: str, path: str) -> bool:
        """True when ``method`` + ``path`` (console path or relay path) is this route."""
        if not isinstance(method, str) or method.strip().upper() not in self.methods:
            return False
        return self._pattern.fullmatch(application_route(path)) is not None


_FE_NETWORK = "Network web UI route inventory (2026-10-11)"
_FE_PROTECT = "Protect web UI route inventory (2026-10-11)"
_LEDGER = "web UI route inventory row"

# Inferred credential keys accepted by N05's arbitrary upstream write bodies.
_N05_SECRET_FIELDS = (
    "password",
    "payment_key",
    "x_password",
    "passphrase",
    "psk",
    "secret",
    "token",
    "private_key",
    "privateKey",
    "preshared_key",
    "presharedKey",
    "api_key",
    "apiKey",
    "credential",
    "credentials",
    "radius_secret",
    "x_radius_secret",
    "x_passphrase",
    "x_psk",
    "auth_password",
)

#: The pairing form submits the owner's account password.
UPS_PAIRING_SECRET = RouteSecret(
    name="ups-pairing-credentials",
    route=r"network/v2/api/ups/pair",
    methods=frozenset({"POST"}),
    request_fields=("password",),
    tool_arguments={"set_ups_pairing": ("password",)},
    relay_path="network/v2/api/ups/pair",
    evidence=(
        "Network web UI 11.0.81 UPS pairing form (chunk 96279) POSTs /v2/api/ups/pair with "
        "{console_mac, username, password, ups_mac}; set_ups_pairing sends the same keys; "
        "N02 UPS pairing POST body password (OP-0587)"
    ),
    verified=True,
)


#: The registry. Add an entry here (never a per-tool patch) for any route that carries a
#: credential; the property test covers it through the relay path automatically.
ROUTE_SECRETS: tuple[RouteSecret, ...] = (
    UPS_PAIRING_SECRET,
    RouteSecret(
        name="protect-camera-webhook-secrets",
        route=r"protect/api/cameras/[^/]+",
        methods=frozenset({"GET"}),
        response_fields=("headers", "auth"),
        relay_path="protect/api/cameras/example",
        evidence="update_camera_shortcut camera response webhook fields",
        verified=True,
    ),
    RouteSecret(
        name="protect-camera-shortcut-webhook-secrets",
        route=r"protect/api/cameras/[^/]+/shortcuts",
        methods=frozenset({"PATCH"}),
        request_fields=("headers", "auth"),
        response_fields=("headers", "auth"),
        relay_path="protect/api/cameras/example/shortcuts",
        evidence="update_camera_shortcut webhook request and response fields",
        verified=True,
    ),
    RouteSecret(
        name="mobility-device-wireless",
        route=r"v1/mobility/workspaces/[^/]+/devices/[^/]+/wireless",
        methods=frozenset({"PUT"}),
        request_fields=("password",),
        relay_path="v1/mobility/workspaces/example/devices/example/wireless",
        evidence="update_mobility_device_wireless request body",
        verified=True,
    ),
    RouteSecret(
        name="hotspot-vouchers-code",
        route=r"network/integration/v1/sites/[^/]+/hotspot/vouchers(?:/[^/]+)?",
        methods=ALL_METHODS,
        response_log_fields=("code",),
        relay_path="network/integration/v1/sites/{site}/hotspot/vouchers",
        evidence="Network integration hotspot vouchers response field code (route-scoped scrub)",
        verified=True,
    ),
    RouteSecret(
        name="network-hotspot-settings",
        route=r"network/api/stat/s/[^/]+/hotspotconfig",
        methods=ALL_METHODS,
        request_fields=_N05_SECRET_FIELDS,
        response_fields=_N05_SECRET_FIELDS,
        relay_path="network/api/stat/s/{site}/hotspotconfig",
        evidence=(
            "N05 hotspotconfig route; credential field names inferred from portal configuration"
        ),
        verified=False,
    ),
    RouteSecret(
        name="network-hotspot-payments",
        route=r"network/api/s/[^/]+/stat/payment",
        methods=ALL_METHODS,
        request_fields=_N05_SECRET_FIELDS,
        response_fields=_N05_SECRET_FIELDS,
        relay_path="network/api/s/{site}/stat/payment",
        evidence="N05 stat/payment route; credential field names inferred from payment records",
        verified=False,
    ),
    RouteSecret(
        name="network-client-guest-classic-writes",
        route=r"network/api/s/[^/]+/(?:rest/(?:dhcpoption|hotspotpackage|portalfile)(?:/[^/]+)?|cmd/(?:stamgr|hotspot))",
        methods=ALL_METHODS,
        request_fields=_N05_SECRET_FIELDS,
        response_fields=_N05_SECRET_FIELDS,
        tool_arguments={
            "create_dhcp_option": ("option",),
            "update_dhcp_option": ("fields",),
            "create_hotspot_package": ("package",),
            "update_hotspot_package": ("fields",),
        },
        relay_path="network/api/s/{site}/rest/hotspotpackage",
        evidence=(
            "N05 Classic write route sweep; credential field names inferred "
            "for arbitrary caller bodies"
        ),
        verified=False,
    ),
    RouteSecret(
        name="network-client-guest-v2-writes",
        route=r"network/v2/api/site/[^/]+/(?:clients/[^/]+/ai-icon|matter/nodes/[^/]+/ai-icon|station/[^/]+/fingerprint_override|(?:station|device)/[^/]+/wifi_experience/incorrect|settings/guest-access/reset)",
        methods=ALL_METHODS,
        request_fields=_N05_SECRET_FIELDS,
        response_fields=_N05_SECRET_FIELDS,
        tool_arguments={
            "set_client_icon": ("icon",),
            "set_client_fingerprint_override": ("override",),
            "reset_guest_access_settings": ("body",),
        },
        relay_path="network/v2/api/site/{site}/settings/guest-access/reset",
        evidence=(
            "N05 v2 write route sweep; credential field names inferred for arbitrary caller bodies"
        ),
        verified=False,
    ),
    RouteSecret(
        name="matter-setup-code",
        route=r"network/v2/api/site/[^/]+/matter/nodes",
        methods=frozenset({"POST"}),
        request_fields=("setup_code",),
        response_fields=("setup_code",),
        tool_arguments={"commission_matter_node": ("setup_code",)},
        relay_path="network/v2/api/site/{site}/matter/nodes",
        evidence="Matter frontend queue GET and commissioning POST: setup_code (route inventory)",
        verified=True,
    ),
    RouteSecret(
        name="matter-node-setup-code",
        route=r"network/v2/api/site/[^/]+/matter/nodes",
        methods=frozenset({"GET"}),
        response_fields=("setup_code",),
        relay_path="network/v2/api/site/{site}/matter/nodes",
        evidence="Matter frontend queue GET response setup_code (route inventory)",
        verified=True,
    ),
    RouteSecret(
        name="protect-share-link",
        route=r"protect/api/cameras/[^/]+/sharedStream",
        methods=ALL_METHODS,
        request_fields=("shareLink", "token"),
        response_fields=("shareLink", "token"),
        response_headers=("location",),
        relay_path="protect/api/cameras/0000000000000000000000aa/sharedStream",
        evidence="live camera share-link probe",
        verified=True,
    ),
    RouteSecret(
        name="protect-camera-share-link",
        route=r"protect/api/cameras/[^/]+",
        methods=frozenset({"GET", "PATCH"}),
        request_fields=("shareLink", "token"),
        response_fields=("shareLink", "token"),
        relay_path="protect/api/cameras/0000000000000000000000aa",
        evidence=f"{_FE_PROTECT} camera streamSharing model: shareLink and token",
        verified=True,
    ),
    RouteSecret(
        name="protect-bootstrap-share-link",
        route=r"protect/api/bootstrap",
        methods=frozenset({"GET"}),
        response_fields=("shareLink", "token"),
        relay_path="protect/api/bootstrap",
        evidence=f"{_FE_PROTECT} bootstrap camera streamSharing model: shareLink and token",
        verified=True,
    ),
    RouteSecret(
        name="classic-advanced-adoption-password",
        route=r"network/api/s/[^/]+/cmd/devmgr",
        methods=frozenset({"POST"}),
        request_fields=("password",),
        tool_arguments={"advanced_adopt_device": ("password",)},
        relay_path="network/api/s/{site}/cmd/devmgr",
        evidence=f"{_FE_NETWORK} cmd/devmgr adv-adopt body password",
        verified=True,
    ),
    RouteSecret(
        name="classic-group-bulk-credentials",
        route=r"network/api/s/[^/]+/group/(?:device|user|networkconf|setting)",
        methods=frozenset({"PUT"}),
        request_fields=(
            "x_ssh_password",
            "x_ssh_sudopassword",
            "x_passphrase",
            "x_password",
            "x_secret",
            "x_radius_secret",
            "x_iapp_key",
            "x_mesh_psk",
            "x_ipsec_pre_shared_key",
            "x_wireguard_private_key",
        ),
        relay_path="network/api/s/{site}/group/setting",
        evidence=(
            f"{_FE_NETWORK} group/device|user|networkconf|setting bulk PUT (N03 "
            "bulk_update_objects): setting objects and networkconf data carry the Classic "
            "rest/setting and rest/networkconf credential fields; key names from the "
            "server's Classic credential field list, not captured on this route"
        ),
    ),
    RouteSecret(
        name="remote-access-turn-credentials",
        route=r"network/api/s/[^/]+/cmd/cloudaccess",
        methods=frozenset({"POST"}),
        request_fields=("ubic_password", "ubic_2fa_token", "mfa_cookie"),
        response_fields=("password", "credential", "credentials", "turn_password"),
        tool_arguments={
            "set_cloud_access_registration": ("ubic_password", "ubic_2fa_token", "mfa_cookie")
        },
        relay_path="network/api/s/{site}/cmd/cloudaccess",
        evidence=(
            f"{_LEDGER} OP cmd/cloudaccess get-turn-credentials/register; request keys from "
            f"the register body in {_FE_NETWORK}; response keys inferred (TURN REST form)"
        ),
    ),
    RouteSecret(
        name="openvpn-client-config",
        route=r"network/v2/api/site/[^/]+/vpn/openvpn/[^/]+/configuration",
        methods=frozenset({"GET"}),
        response_fields=("configuration", "openvpn_configuration", "content"),
        response_body=True,
        relay_path="network/v2/api/site/{site}/vpn/openvpn/0000000000000000000000aa/configuration",
        evidence=(
            f"{_LEDGER} GET vpn/openvpn/{{id}}/configuration; {_FE_NETWORK} parses "
            "openvpn_configuration into certificate, privateKey and vpnKey"
        ),
    ),
    RouteSecret(
        name="wireguard-user-keys",
        route=r"network/v2/api/site/[^/]+/wireguard(?:/[^/]+)?/users(?:/batch|/batch_delete)?",
        methods=ALL_METHODS,
        request_fields=("private_key", "privateKey", "preshared_key", "presharedKey"),
        response_fields=("private_key", "privateKey", "preshared_key", "presharedKey"),
        relay_path="network/v2/api/site/{site}/wireguard/0000000000000000000000aa/users/batch",
        evidence=(
            f"{_LEDGER} wireguard/{{id}}/users/batch; {_FE_NETWORK} builds the peer config "
            "from privateKey and presharedKey"
        ),
    ),
    RouteSecret(
        name="wifi-wan-uplink-password",
        route=r"network/api/s/[^/]+/rest/networkconf(?:/[^/]+)?",
        methods=frozenset({"PUT"}),
        request_fields=("x_uplink_password",),
        response_fields=("x_uplink_password",),
        tool_arguments={"configure_wifi_wan": ("x_uplink_password",)},
        relay_path="network/api/s/{site}/rest/networkconf/0000000000000000000000aa",
        evidence="Network 11 gap-contract WiFi-WAN form: x_uplink_password",
        verified=True,
    ),
    RouteSecret(
        name="bgp-config-password",
        route=r"network/v2/api/site/[^/]+/bgp/config(?:/[^/]+)?",
        methods=frozenset({"GET", "POST"}),
        request_fields=("password",),
        response_fields=("password",),
        relay_path="network/v2/api/site/{site}/bgp/config",
        evidence=(
            f"{_LEDGER} GET bgp/config/all, POST bgp/config and bgp/config/{{id}} "
            "(body_dynamic, no captured keys); key name inferred from BGP neighbour "
            "password authentication (RFC 2385 TCP MD5), unconfirmed"
        ),
    ),
    RouteSecret(
        name="ospf-router-password",
        route=r"network/v2/api/site/[^/]+/ospf/router(?:/[^/]+)?",
        methods=frozenset({"GET", "POST", "PUT"}),
        request_fields=("password",),
        response_fields=("password",),
        relay_path="network/v2/api/site/{site}/ospf/router",
        evidence=(
            f"{_LEDGER} GET/POST ospf/router and PUT ospf/router/{{id}} (body_dynamic, no "
            "captured keys); key name inferred from OSPF interface authentication "
            "(RFC 2328 simple/MD5 key), unconfirmed"
        ),
    ),
    RouteSecret(
        name="wireguard-networkconf-keys",
        route=r"network/api/s/[^/]+/rest/networkconf(?:/[^/]+)?",
        methods=ALL_METHODS,
        request_fields=(
            "x_wireguard_private_key",
            "wireguard_private_key",
            "wireguard_client_preshared_key",
            "openvpn_configuration",
        ),
        response_fields=(
            "x_wireguard_private_key",
            "wireguard_private_key",
            "wireguard_client_preshared_key",
            "openvpn_configuration",
        ),
        relay_path="network/api/s/{site}/rest/networkconf/0000000000000000000000aa",
        evidence=f"{_FE_NETWORK} VPN client form reads x_wireguard_private_key",
        verified=True,
    ),
    RouteSecret(
        name="teleport-token",
        route=r"network/v2/api/site/[^/]+/teleport/token(?:/[^/]+)?",
        methods=frozenset({"GET", "POST", "DELETE"}),
        response_fields=("token", "teleportToken", "link", "url", "invitation_link"),
        relay_path="network/v2/api/site/{site}/teleport/token",
        evidence=f"{_LEDGER} POST teleport/token; {_FE_NETWORK} teleportToken; keys inferred",
    ),
    RouteSecret(
        name="teleport-invitation-history",
        route=r"network/v2/api/site/[^/]+/teleport/invitation-history",
        methods=frozenset({"POST"}),
        response_fields=("token", "teleportToken", "link", "url", "invitation_link"),
        relay_path="network/v2/api/site/{site}/teleport/invitation-history",
        evidence=(
            f"{_LEDGER} POST teleport/invitation-history (pageNumber, pageSize); response "
            "keys inferred from the teleport-token entry"
        ),
    ),
    RouteSecret(
        name="ipsec-settings-psk",
        route=r"network/v2/api/site/[^/]+/settings/ipsec",
        methods=frozenset({"GET", "POST"}),
        request_fields=("x_ipsec_pre_shared_key", "ipsec_pre_shared_key", "pre_shared_key"),
        response_fields=("x_ipsec_pre_shared_key", "ipsec_pre_shared_key", "pre_shared_key"),
        relay_path="network/v2/api/site/{site}/settings/ipsec",
        evidence=(
            f"{_LEDGER} GET and POST settings/ipsec; key names inferred from the Classic "
            "networkconf x_ipsec_pre_shared_key spelling"
        ),
    ),
    RouteSecret(
        name="site-vpn-psk",
        route=r"network/api/s/[^/]+/cmd/sitemgr",
        methods=frozenset({"POST"}),
        request_fields=("x_ipsec_pre_shared_key", "ipsec_pre_shared_key", "pre_shared_key"),
        relay_path="network/api/s/{site}/cmd/sitemgr",
        evidence=(
            f"{_LEDGER} cmd/sitemgr add-site-vpn (dynamic body); key names inferred from "
            "the Classic networkconf x_ipsec_pre_shared_key spelling"
        ),
    ),
    RouteSecret(
        name="ssl-inspection-private-key",
        route=(
            r"network/v2/api/site/[^/]+/ssl-inspection/certificates"
            r"(?:/generate|/[^/]+(?:/activate)?)?"
        ),
        methods=ALL_METHODS,
        request_fields=("private_key", "privateKey", "key", "passphrase", "password"),
        response_fields=("private_key", "privateKey", "key", "passphrase"),
        relay_path="network/v2/api/site/{site}/ssl-inspection/certificates",
        evidence=f"{_LEDGER} ssl-inspection/certificates POST/generate; keys inferred",
    ),
    RouteSecret(
        name="classic-admin-credentials",
        route=r"network/api/s/[^/]+/cmd/(?:sitemgr|lte|productinfo/refresh-sso)",
        methods=frozenset({"POST"}),
        request_fields=(
            "x_password",
            "x_ubic_password",
            "ubic_2fa_token",
            "sso_password",
            "sso_2fa_token",
            "mfa_cookie",
        ),
        tool_arguments={
            "refresh_sso_session": ("sso_password", "sso_2fa_token", "mfa_cookie"),
        },
        relay_path="network/api/s/{site}/cmd/sitemgr",
        evidence=(
            f"{_LEDGER} cmd/sitemgr create-admin, cmd/lte auth-device, "
            "cmd/productinfo/refresh-sso body expressions"
        ),
        verified=True,
    ),
    RouteSecret(
        name="classic-test-mail-smtp-password",
        route=r"network/api/s/[^/]+/cmd/cfgmgr",
        methods=frozenset({"POST"}),
        request_fields=("x_password",),
        tool_arguments={"send_test_email": ("x_password",)},
        relay_path="network/api/s/{site}/cmd/cfgmgr",
        evidence=f"{_FE_NETWORK} cmd/cfgmgr test_mail body x_password (N01)",
        verified=True,
    ),
    RouteSecret(
        name="classic-ubic-sso-link-credentials",
        route=r"network/api/s/[^/]+/self/ubic_sso",
        methods=frozenset({"POST"}),
        request_fields=("x_ubic_password", "ubic_2fa_token", "mfa_cookie"),
        tool_arguments={
            "link_ubiquiti_sso_account": ("x_ubic_password", "ubic_2fa_token", "mfa_cookie")
        },
        relay_path="network/api/s/{site}/self/ubic_sso",
        evidence=(
            f"{_FE_NETWORK} self/ubic_sso body x_ubic_password, ubic_2fa_token, mfa_cookie (N01)"
        ),
        verified=True,
    ),
    RouteSecret(
        name="lte-cloud-account-credentials",
        route=r"network/api/s/[^/]+/cmd/lte",
        methods=frozenset({"POST"}),
        request_fields=("x_ubic_password", "ubic_2fa_token"),
        tool_arguments={
            "get_lte_subscription_status": ("ubic_password", "ubic_2fa_token"),
            "authorize_lte_device": ("ubic_password", "ubic_2fa_token"),
        },
        relay_path="network/api/s/{site}/cmd/lte",
        evidence=(
            f"{_FE_NETWORK} N04 cmd/lte auth-device and check-subscription static body keys "
            "x_ubic_password, ubic_2fa_token (11.0.81 chunks 84382 / 97)"
        ),
        verified=True,
    ),
    RouteSecret(
        name="sim-pin",
        route=r"network/api/s/[^/]+/cmd/(?:lte|mbb)",
        methods=frozenset({"POST"}),
        request_fields=("pin",),
        tool_arguments={"verify_sim_pin": ("pin",)},
        relay_path="network/api/s/{site}/cmd/lte",
        evidence=(
            f"{_FE_NETWORK} N04 cmd/lte lte-verify-pin static body keys cmd, mac, pin "
            "(11.0.81 swai bundle); cmd/mbb verify-pin body is dynamic, pin inferred"
        ),
        verified=True,
    ),
    RouteSecret(
        name="lte-apn-credentials",
        route=r"network/api/s/[^/]+/cmd/lte",
        methods=frozenset({"POST"}),
        request_fields=("password", "x_password", "apn_password", "x_apn_password"),
        relay_path="network/api/s/{site}/cmd/lte",
        evidence=(
            f"{_FE_NETWORK} N04 cmd/lte lte-set-profile body is dynamic (11.0.81 swai "
            "bundle); APN credential key names inferred"
        ),
    ),
    RouteSecret(
        name="esim-activation-code",
        route=r"network/api/s/[^/]+/cmd/mbb",
        methods=frozenset({"POST"}),
        request_fields=(
            "activation_code",
            "activationCode",
            "matching_id",
            "matchingId",
            "confirmation_code",
            "confirmationCode",
        ),
        relay_path="network/api/s/{site}/cmd/mbb",
        evidence=(
            f"{_FE_NETWORK} N04 cmd/mbb esim-add body is dynamic (11.0.81 chunks 16723 / "
            "28445); eSIM activation-code key names inferred (GSMA SGP.22 LPA fields)"
        ),
    ),
    RouteSecret(
        name="protect-device-password",
        route=r"protect/api/nvr/device-password",
        methods=frozenset({"GET", "PATCH"}),
        request_fields=("devicePassword",),
        response_fields=("devicePassword", "password"),
        tool_arguments={"update_protect_device_password": ("device_password",)},
        relay_path="protect/api/nvr/device-password",
        evidence=f"{_FE_PROTECT} changeDevicePassword sends {{devicePassword}}",
        verified=True,
    ),
    RouteSecret(
        name="protect-stream-url-token",
        route=r"protect/api/(?:ws/(?:livestream|playback|heatmap|liveDetectTrack|timelapse)"
        r"|video/live|tcp/video/prepare)",
        methods=frozenset({"GET"}),
        response_fields=("url", "directUrl", "alias"),
        response_headers=("location",),
        relay_path="protect/api/ws/livestream",
        evidence=f"{_FE_PROTECT} getWSPath; GS3 P04 recorded stream responses "
        "contain url/directUrl or alias; stream redirects carry Location",
        verified=True,
    ),
    RouteSecret(
        name="protect-camera-adoption-qr-wifi-password",
        route=r"protect/api/cameras/qr",
        methods=frozenset({"GET"}),
        request_fields=("password",),
        tool_arguments={"get_camera_adoption_qr": ("wifi_password",)},
        relay_path="protect/api/cameras/qr",
        evidence=(
            f"{_FE_PROTECT} GET cameras/qr query keys ssid, password "
            "(inventory_protect_5.3.18.json, swai.js 2054221); the WiFi password travels "
            "as the password query parameter"
        ),
        verified=True,
    ),
    RouteSecret(
        name="protect-camera-wifi-setup-password",
        route=r"protect/api/cameras/[^/]+/wifi-setup",
        methods=frozenset({"POST"}),
        request_fields=("password", "passphrase"),
        relay_path="protect/api/cameras/0000000000000000000000aa/wifi-setup",
        evidence=(
            f"{_FE_PROTECT} POST cameras/{{id}}/wifi-setup (swai.js 2054416) sends a dynamic "
            "body; key names inferred from the adoption QR's ssid/password query keys"
        ),
    ),
    RouteSecret(
        name="protect-rtsps-stream-url",
        route=r"protect/integration/v1/cameras/[^/]+/rtsps-stream",
        methods=frozenset({"GET", "POST", "DELETE"}),
        response_fields=("high", "medium", "low", "package"),
        relay_path="protect/integration/v1/cameras/0000000000000000000000aa/rtsps-stream",
        evidence="Protect 7.3.70 spec createdRtspsStreams / existingRtspsStreams",
        verified=True,
    ),
    RouteSecret(
        name="protect-backup-secrets",
        route=r"protect/api/(?:backups(?:/[^/]+(?:/(?:restore|download|export))?)?|nvr/(?:backup|restore-pg-dump))",
        methods=ALL_METHODS,
        request_fields=(
            "credentials",
            "key",
            "keys",
            "apiKey",
            "privateKey",
            "password",
            "passwords",
            "token",
            "tokens",
            "accessToken",
            "refreshToken",
            "secret",
            "secrets",
            "authToken",
            "clientSecret",
            "sshPrivateKey",
            "devicePassword",
            "encryptionKey",
        ),
        response_fields=(
            "credentials",
            "key",
            "keys",
            "apiKey",
            "privateKey",
            "password",
            "passwords",
            "token",
            "tokens",
            "accessToken",
            "refreshToken",
            "secret",
            "secrets",
            "authToken",
            "clientSecret",
            "sshPrivateKey",
            "devicePassword",
            "encryptionKey",
        ),
        response_body=True,
        relay_path="protect/api/backups/import",
        evidence=f"{_FE_PROTECT} backup import/export routes; secret field names inferred",
    ),
    RouteSecret(
        name="protect-cloud-archive-credentials",
        route=r"protect/api/cloud-provider/(?:authenticate|authenticate-device-code|authenticate-nas)",
        methods=frozenset({"GET", "POST"}),
        request_fields=("code", "password", "token", "secret"),
        response_fields=("url", "authUrl", "token", "accessToken", "refreshToken"),
        tool_arguments={"connect_cloud_archive_provider": ("code",)},
        relay_path="protect/api/cloud-provider/authenticate-device-code",
        evidence=(
            f"{_FE_PROTECT} authenticateDeviceCode sends {{code}}; authenticateNAS body and "
            "response keys inferred"
        ),
    ),
    RouteSecret(
        name="protect-third-party-camera-credentials",
        route=r"protect/api/third-party-cameras/adopt",
        methods=frozenset({"POST"}),
        request_fields=("password", "pass", "passwd"),
        response_fields=("password",),
        relay_path="protect/api/third-party-cameras/adopt",
        evidence=(
            f"{_FE_PROTECT} POST third-party-cameras/adopt (body built at run time); the "
            "camera login key names are inferred (GS3 P01 adopt_third_party_camera)"
        ),
    ),
    RouteSecret(
        name="protect-keyring-registry-id",
        route=r"protect/api/keyrings",
        methods=frozenset({"GET"}),
        response_fields=("registryId",),
        relay_path="protect/api/keyrings",
        evidence=(
            f"{_FE_PROTECT} GET keyrings (NFC card / fingerprint keyrings); the registryId "
            "key name is inferred (GS3 P01 list_protect_keyrings)"
        ),
    ),
    RouteSecret(
        name="protect-ufv-credentials",
        route=r"protect/api/ufv/[^/]+/(?:login|bootstrap)",
        methods=frozenset({"GET", "POST"}),
        request_fields=("password", "token", "apiKey"),
        response_fields=("token", "authToken", "apiKey"),
        relay_path="protect/api/ufv/0000000000000000000000aa/login",
        evidence=f"{_FE_PROTECT} loginToLegacyNvr posts a login body; keys inferred",
    ),
    RouteSecret(
        name="protect-doorbell-credentials",
        route=r"protect/api/cameras/[^/]+/(?:nfc|fingerprint)/[^/]+",
        methods=frozenset({"POST"}),
        request_fields=("fingerprintId",),
        tool_arguments={
            "enroll_doorbell_credential": ("fingerprint_id",),
        },
        relay_path="protect/api/cameras/0000000000000000000000aa/fingerprint/assign",
        evidence=(
            f"{_FE_PROTECT} (Protect UI 5.3.18) fingerprint/assign sends {{fingerprintId, "
            "ulpId}}; the enrolled NFC card / fingerprint id is the DELETE path id"
        ),
        verified=True,
    ),
    RouteSecret(
        name="protect-doorbell-delete-credential",
        route=r"protect/api/cameras/[^/]+/(?:nfc|fingerprint)/(?P<credential_id>[^/]+)",
        methods=frozenset({"DELETE"}),
        request_path_groups=("credential_id",),
        tool_arguments={"delete_doorbell_credential": ("credential_id",)},
        relay_path="protect/api/cameras/0000000000000000000000aa/fingerprint/fixture-id",
        evidence=f"{_FE_PROTECT} enrolled NFC card / fingerprint id is the DELETE path id",
        verified=True,
    ),
    RouteSecret(
        name="innerspace-shared-project-token",
        route=r"innerspace/api/import/projects/(?P<token>[^/]+)",
        methods=frozenset({"POST"}),
        request_path_groups=("token",),
        tool_arguments={"import_innerspace_shared_project": ("token",)},
        relay_path="innerspace/api/import/projects/3fa85f64-5717-4562-b3fc-2c963f66afa6",
        evidence=(
            "InnerSpace route inventory: import.sharedProject POST "
            "/api/import/projects/:token; the share token is a path segment, no body field"
        ),
    ),
)


# Expose every compiled registry pattern to the ReDoS lint's module-global scan.
ROUTE_PATTERNS = tuple(entry._pattern for entry in ROUTE_SECRETS)


def application_route(path: str) -> str:
    """The application route of a console path or relay path (see :class:`RouteSecret`)."""
    text = path.split("?", 1)[0].strip()
    if _PROXY_MARK in text:
        text = text.split(_PROXY_MARK, 1)[1]
    return text.strip("/")


def matching(method: str, path: str) -> tuple[RouteSecret, ...]:
    """Every registry entry for ``method`` + ``path``."""
    # Imported here: ``client`` imports this module for its request/response masking.
    from .client import describe_shape

    for argument, value in (("method", method), ("path", path)):
        if not isinstance(value, str):
            # Client binds through this module; defer its shape helper to avoid
            # a client-first import cycle during module initialization.
            from .client import describe_shape

            raise ValueError(
                f"Route secret matching: {argument} must be a string, got {describe_shape(value)}"
            )
    return tuple(entry for entry in ROUTE_SECRETS if entry.matches(method, path))


def _secret_text(value: Any) -> str | None:
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value
    return None


def _walk(body: Any, names: frozenset[str], seen: set[int] | None = None) -> Iterator[str]:
    """Yield named secret values without recursing through cyclic caller data."""
    if seen is None:
        seen = set()
    if isinstance(body, Mapping | list | tuple):
        ident = id(body)
        if ident in seen:
            return
        seen.add(ident)
    if isinstance(body, Mapping):
        for key, value in body.items():
            if key in names:
                yield from _secret_leaves(value, seen)
                continue
            yield from _walk(value, names, seen)
    elif isinstance(body, (list, tuple)):
        for item in body:
            yield from _walk(item, names, seen)


def _secret_leaves(value: Any, seen: set[int] | None = None) -> Iterator[str]:
    """Every scalar credential within a registered credential field (cycle-safe)."""
    if seen is None:
        seen = set()
    if isinstance(value, Mapping | list | tuple):
        ident = id(value)
        if ident in seen:
            return
        seen.add(ident)
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _secret_leaves(item, seen)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _secret_leaves(item, seen)
    else:
        text = _secret_text(value)
        if text is not None:
            yield text


def _request_names(method: str, path: str) -> frozenset[str]:
    return frozenset(name for entry in matching(method, path) for name in entry.request_fields)


def _request_path_spans(method: str, path: str) -> Iterator[tuple[int, int]]:
    """Credential spans in the original path, preserving its prefix and query spelling."""
    entries = matching(method, path)
    route = application_route(path)
    offset = path.split("?", 1)[0].rfind(route)
    for entry in entries:
        match = entry._pattern.fullmatch(route)
        if match is not None:
            for group in entry.request_path_groups:
                start, end = match.span(group)
                if start >= 0 and end > start:
                    yield offset + start, offset + end


def request_path_secrets(method: str, path: str) -> tuple[str, ...]:
    """Registered credential segments of a typed or relayed request path."""
    return tuple(dict.fromkeys(path[start:end] for start, end in _request_path_spans(method, path)))


def mask_request_path(method: str, path: str, /, *, redact_secrets: bool) -> str:
    """Mask only registered credential segments under the operator's redaction opt-in."""
    if not redact_secrets:
        return path
    for start, end in sorted(set(_request_path_spans(method, path)), reverse=True):
        path = path[:start] + MASK + path[end:]
    return path


def request_secrets(method: str, path: str, body: Any) -> tuple[str, ...]:
    """The credential values in the request path and body (for error/log scrubbing)."""
    names = _request_names(method, path)
    body_values = _walk(body, names) if names else ()
    return tuple(dict.fromkeys((*request_path_secrets(method, path), *body_values)))


def _mask(body: Any, names: frozenset[str]) -> Any:
    if isinstance(body, Mapping):
        return {
            key: MASK if key in names and any(_secret_leaves(item)) else _mask(item, names)
            for key, item in body.items()
        }
    if isinstance(body, list):
        return [_mask(item, names) for item in body]
    return body


def mask_request_body(method: str, path: str, body: Any, /, *, redact_secrets: bool) -> Any:
    """``body`` with listed request values masked, ONLY when ``redact_secrets`` is on.

    ``redact_secrets`` is the operator's ``UNIFI_REDACT_SECRETS`` opt-in. Off (the default)
    returns ``body`` itself, unchanged. On returns a masked copy.
    """
    if not redact_secrets:
        return body
    names = _request_names(method, path)
    return _mask(body, names) if names else body


def mask_response_body(method: str, path: str, body: Any, /, *, redact_secrets: bool) -> Any:
    """``body`` with listed route-secret values masked only when ``redact_secrets`` is on.

    Both response fields and echoed request fields are route-secret values. A text body
    on a ``response_body`` route is replaced by the mask under the opt-in. Off (the
    default) returns ``body`` itself, unchanged.
    """
    if not redact_secrets:
        return body
    entries = matching(method, path)
    if not entries:
        return body
    if isinstance(body, str) and any(entry.response_body for entry in entries):
        return MASK if body.strip() else body
    names = frozenset(
        name for entry in entries for name in (*entry.request_fields, *entry.response_fields)
    )
    return _mask(body, names) if names else body


def _response_text(content: bytes, content_type: str | None) -> str | None:
    # Import lazily: the client consumes this registry. Share its declared-charset
    # policy rather than guessing UTF-8 or accepting non-character-set transforms.
    from .client import declared_text_codec

    encoding = declared_text_codec(content_type)
    if encoding is None:
        return None
    try:
        return content.decode(encoding, errors="strict")
    except (UnicodeError, LookupError):
        return None


def _json_body(text: str | None) -> Any:
    try:
        return json.loads(text.removeprefix("\ufeff")) if text is not None else None
    except ValueError:
        return None


def response_secrets(
    method: str,
    path: str,
    content: bytes,
    headers: Iterable[tuple[str, str]],
    *,
    status_code: int = 200,
) -> tuple[str, ...]:
    """The credential values an upstream response to ``method`` + ``path`` carries.

    The listed response fields and an echoed request field (the same credential handed
    back) count, as :func:`mask_response_body` masks both. A whole-body credential
    (``response_body``) counts only for a 2xx ``status_code``. For a non-2xx
    ``status_code`` only the listed response fields (and headers) count: an echoed
    request field in an error is bound by value from the request; key-name discovery on
    an error body covers upstream-returned credentials only. Every entry of the route
    counts, whatever its methods: a write's read-before / read-after GET returns the
    credential the write registers (scrubbing only, never structured masking).
    """
    matching(method, path)  # validates both argument shapes
    entries = tuple(
        entry for entry in ROUTE_SECRETS if any(entry.matches(m, path) for m in entry.methods)
    )
    if not entries:
        return ()
    if 200 <= status_code < 300:
        fields = frozenset(
            name for entry in entries for name in (*entry.request_fields, *entry.response_fields)
        )
    else:
        fields = frozenset(name for entry in entries for name in entry.response_fields)
    header_names = frozenset(name.lower() for entry in entries for name in entry.response_headers)
    values: list[str] = []
    headers = tuple(headers)
    content_type = next((value for name, value in headers if name.lower() == "content-type"), None)
    text = _response_text(content, content_type) if content else None
    parsed = _json_body(text)
    if fields and parsed is not None:
        values.extend(_walk(parsed, fields))
    if 200 <= status_code < 300 and any(entry.response_body for entry in entries):
        if isinstance(parsed, str) and parsed.strip():
            values.append(parsed)
        elif parsed is None and text and text.strip():
            values.append(text)
    for name, value in headers:
        if name.lower() in header_names and value.strip():
            values.append(value)
    return tuple(dict.fromkeys(values))


#: Relay tool -> the HTTP method it sends.
RELAY_TOOLS: Mapping[str, str] = {
    "fabric_connector_get": "GET",
    "fabric_connector_post": "POST",
    "fabric_connector_put": "PUT",
    "fabric_connector_patch": "PATCH",
    "fabric_connector_delete": "DELETE",
}


def tool_call_secrets(tool: str, arguments: Mapping[str, Any]) -> tuple[str, ...]:
    """The listed credentials a tool call's raw arguments carry, before any validation.

    A typed tool's listed arguments (:attr:`RouteSecret.tool_arguments`), and for a relay
    tool the listed request fields of ``body`` and of the ``params`` query when ``path`` is
    a listed route (a GET route carries its request field as a query parameter).
    """
    values: list[str] = []
    for entry in ROUTE_SECRETS:
        for name in entry.tool_arguments.get(tool, ()):
            value = arguments.get(name)
            if isinstance(value, Mapping | list | tuple):
                values.extend(_walk(value, frozenset(entry.request_fields)))
                continue
            text = _secret_text(value)
            if text is not None:
                values.append(text)
    method = RELAY_TOOLS.get(tool)
    path = arguments.get("path")
    if method is not None and isinstance(path, str):
        values.extend(request_secrets(method, path, arguments.get("body")))
        values.extend(request_secrets(method, path, arguments.get("params")))
    return tuple(dict.fromkeys(values))


def bind_request(method: str, path: str, body: Any, params: Any = None) -> None:
    """Bind the registered request values of ``body`` and of the ``params`` query into the
    current call's scrub scope (an echoed request field is bound by value from the request,
    wherever the route carries it)."""
    add_call_secrets(request_secrets(method, path, body) + request_secrets(method, path, params))


def bind_response(
    method: str,
    path: str,
    content: bytes,
    headers: Iterable[tuple[str, str]],
    *,
    status_code: int,
) -> None:
    """Bind the registered response values into the current call's scrub scope.

    A whole-body credential binds only for a 2xx response: error HTML remains diagnostic
    text, scrubbed of the individually bound values.
    """
    headers = tuple(headers)
    names = frozenset(
        name for entry in matching(method, path) for name in entry.response_log_fields
    )
    if names:
        content_type = next(
            (value for name, value in headers if name.lower() == "content-type"), None
        )
        parsed = _json_body(_response_text(content, content_type))
        add_log_secrets(_walk(parsed, names))
    add_call_secrets(response_secrets(method, path, content, headers, status_code=status_code))
