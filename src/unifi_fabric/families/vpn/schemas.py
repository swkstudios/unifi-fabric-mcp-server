"""The vpn family's DNS tool shapes: routes, record lookup and argument types (public #42 layout).

The DNS handlers (``handlers.py``) and their registrar (``registrar.py``) share these. An
argument type here is a plain alias, so the advertised input schema is the one the type
itself gives (a static DNS record is a free-form JSON object: no published schema).
"""

from __future__ import annotations

from typing import Any, Literal

#: The v2 static DNS record collection.
STATIC_DNS = "/static-dns"
#: The v2 DNS-over-HTTPS server-name list.
DOH_SERVER_NAMES = "/settings/doh/available-server-names"

#: A static DNS record body: free-form, sent verbatim (no published schema).
StaticDnsRecord = dict[str, Any]

#: How a static DNS record id is resolved in the listed collection and named in errors.
STATIC_DNS_RECORD_KIND = "Static DNS record"
STATIC_DNS_LIST_TOOL = "list_static_dns_records"
STATIC_DNS_LABEL_FIELDS: tuple[str, ...] = ("key", "name")

#: Site VPN actions on Classic ``cmd/sitemgr`` (``<action>-site-vpn``).
SiteVpnAction = Literal["enable", "disable", "rebuild"]
_SITE_VPN_ACTIONS = ("enable", "disable", "rebuild")

_TEXT_TYPES = ("text/", "application/json", "application/x-openvpn-profile")

_S2S = "site-vpn"

# Short VPN type names (the Integration list reports WIREGUARD / OPENVPN / L2TP) mapped to
# the controller's networkconf vpn_type values. Any other value is sent unchanged.
_VPN_SERVER_TYPES = {
    "wireguard": "wireguard-server",
    "openvpn": "openvpn-server",
    "l2tp": "l2tp-server",
    "pptp": "pptp-server",
}

_VPN_CLIENT = "vpn-client"
_KIND = "VPN client"
_LIST_TOOL = "list_vpn_clients"

# Short VPN client type names mapped to the controller's networkconf vpn_type values
# (go-unifi Network.VPNType). Any other value is sent unchanged.
_VPN_CLIENT_TYPES = {
    "wireguard": "wireguard-client",
    "openvpn": "openvpn-client",
    "pptp": "pptp-client",
}

#: Hint appended to an upstream error of a create: the fields the live probe needed.
_CREATE_HINT = (
    "create_vpn_client: a manual WireGuard client (vpn_type wireguard) needs, in fields, "
    "wireguard_client_mode 'manual', wireguard_client_peer_ip, wireguard_client_peer_port, "
    "wireguard_client_peer_public_key, x_wireguard_private_key, ip_subnet (the tunnel "
    "address, e.g. 10.8.0.2/32) and an interface DNS server: dhcpd_dns_enabled true with "
    "dhcpd_dns_1 (api.err.WireguardMissingInterfaceDns without it). An OpenVPN client takes "
    "openvpn_configuration (the .ovpn text) and, when the server asks, openvpn_username / "
    "x_openvpn_password."
)
