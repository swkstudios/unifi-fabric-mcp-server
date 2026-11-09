#!/usr/bin/env python3
"""Hermetic synthetic API fixture for product documentation checks."""

from __future__ import annotations

import argparse
import base64
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

API_KEY = "api-key-1"
FIXTURES = Path(__file__).with_name("fixtures.json")
CONSOLE = re.compile(r"^/v1/connector/consoles/(?P<host>[^/]+)/proxy/(?P<rest>.*)\Z")
TRACE = "0" * 30 + "de"
# Placeholder ids that docs/TOOL-USAGE.md uses in its examples. The mock answers them so
# every documented example is runnable; each is an OpenAPI sample value, not a real id.
DOC_UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
DOC_CAMERA_ID = "66d025b301ebc903e80003ea"
DOC_TASK_ID = "5f0c4d2e8b1a2c3d4e5f6a7c"
# Fixed synthetic ids for the Site Manager, Carrier and Mobility objects.
SDWAN_CONFIG_ID = "00000000-0000-6000-a000-000000000001"
CARRIER_SUBSCRIBER_ID = "00000000-0000-7000-a000-000000000001"
CARRIER_PLAN_ID = "00000000-0000-7000-a000-000000000002"
MOBILITY_WORKSPACE_ID = "00000000-0000-8000-a000-000000000001"
MOBILITY_DEVICE_ID = "00000000-0000-8000-a000-000000000002"
# Classic cmd reads the mock answers: (route, command) pairs the server sends as read-POSTs.
CLASSIC_READ_COMMANDS = {
    ("firmware", "list-available"): [
        {"model": "U6-Pro", "version": "6.9.2", "channel": "release", "upgradable": True}
    ],
    ("firmware", "list-cached"): [],
    ("backup", "list-backups"): [
        {"filename": "autobackup_demo.unf", "time": 1791700000, "size": 1048576, "type": "auto"}
    ],
    ("devmgr", "speedtest-status"): [
        {
            "latency": 9,
            "rundate": 1791700000,
            "runtime": 15,
            "status_download": 2,
            "status_ping": 2,
            "status_summary": 2,
            "xput_download": 480.2,
            "xput_upload": 96.4,
        }
    ],
}
NOW = 1791703200  # 2026-10-11T06:00:00Z, fixed so every run serves the same data


def mac(console: int, device: int) -> str:
    """Locally administered demo MAC: 02:00:5e:<console>:<hi>:<lo>."""
    return ":".join(
        ["02", "00", "5e", f"{console:02x}", f"{device >> 8:02x}", f"{device & 0xFF:02x}"]
    )


def uuid(kind: int, console: int, n: int) -> str:
    return f"00000000-0000-{kind}000-a000-{console:04d}{n:08d}"


def object_id(console: int, n: int) -> str:
    return f"{'0' * 16}{console:02x}{n:06x}"


def snapshot_image() -> tuple[bytes, str]:
    """A synthetic one-pixel PNG, with no production imagery."""
    data = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
        "/x8AAwMCAO+/aQAAAABJRU5ErkJggg=="
    )
    return base64.b64decode(data), "image/png"


def build(fixtures: dict) -> dict:
    hosts, sites, devices, consoles = [], [], [], {}
    for c, con in enumerate(fixtures["consoles"], start=1):
        host_id = f"{'0' * 48}02005E{c:02X}0000:{c:010d}"
        lan = f"198.51.100.{c * 20}"
        hosts.append(
            {
                "id": host_id,
                "hardwareId": uuid(5, c, 0),
                "type": "console",
                "ipAddress": con["wanIp"],
                "owner": True,
                "isBlocked": False,
                "registrationTime": "2024-03-01T09:00:00Z",
                "lastConnectionStateChange": "2026-10-09T19:22:04Z",
                "latestBackupTime": "2026-10-11T03:00:00Z",
                "reportedState": {
                    "hostname": con["hostname"],
                    "name": con["name"],
                    "state": "connected",
                    "version": con["osVersion"],
                    "ip": lan,
                    "mac": mac(c, 0).replace(":", "").upper(),
                    "timezone": "Etc/UTC",
                    "hardware": {
                        "shortname": con["shortname"],
                        "firmwareVersion": con["osVersion"],
                    },
                },
            }
        )
        counts = {
            "criticalNotification": 0,
            "gatewayDevice": 1,
            "guestClient": con["clients"]["guest"],
            "offlineDevice": 0,
            "offlineGatewayDevice": 0,
            "offlineWifiDevice": 0,
            "offlineWiredDevice": 0,
            "pendingUpdateDevice": 0,
            "totalDevice": 0,
            "wifiClient": con["clients"]["wifi"],
            "wiredClient": con["clients"]["wired"],
            "wifiDevice": 0,
            "wiredDevice": 0,
        }
        wrapper, net_devices, classic_devices, cameras = [], [], [], []
        by_name = {}
        for d, dev in enumerate(con["devices"]):
            offline = dev["status"] != "online"
            is_ap = "radios" in dev or dev["model"].startswith(("U6", "U7", "U5G"))
            ip = "" if offline else f"198.51.100.{c * 20 + d}"
            dmac = mac(c, d)
            by_name[dev["name"]] = (d, dmac)
            if dev["productLine"] == "network":
                counts["totalDevice"] += 1
                if not dev.get("isConsole"):
                    counts["wifiDevice" if is_ap else "wiredDevice"] += 1
                if offline:
                    counts["offlineDevice"] += 1
                    counts["offlineWifiDevice" if is_ap else "offlineWiredDevice"] += 1
                if dev["firmwareStatus"] == "updateAvailable":
                    counts["pendingUpdateDevice"] += 1
                net_devices.append(
                    {
                        "id": uuid(3, c, d),
                        "macAddress": dmac,
                        "ipAddress": ip,
                        "name": dev["name"],
                        "model": dev["model"],
                        "state": "OFFLINE" if offline else "ONLINE",
                        "supported": True,
                        "firmwareVersion": dev["version"] or "6.9.1",
                        "firmwareUpdatable": dev["firmwareStatus"] == "updateAvailable",
                        "features": ["accessPoint"] if is_ap else ["switching"],
                        "interfaces": ["ports"],
                    }
                )
                radios = [
                    {
                        "name": f"wifi{i}",
                        "radio": r["radio"],
                        "channel": r["channel"],
                        "last_channel": r["channel"],
                        "bw": r["bw"],
                        "last_bw": r["bw"],
                        "cu_total": r["cu_total"],
                        "cu_interf": r["cu_interf"],
                        "cu_self_rx": max(0, (r["cu_total"] - r["cu_interf"]) // 2),
                        "cu_self_tx": max(
                            0,
                            r["cu_total"] - r["cu_interf"] - (r["cu_total"] - r["cu_interf"]) // 2,
                        ),
                        "tx_retries_pct": r["tx_retries_pct"],
                        "num_sta": r["num_sta"],
                        "user-num_sta": r["num_sta"],
                        "guest-num_sta": 0,
                        "state": "RUN",
                        "tx_power": 14,
                        "satisfaction": -1,
                    }
                    for i, r in enumerate(dev.get("radios", []))
                ]
                classic_devices.append(
                    {
                        "_id": object_id(c, d),
                        "mac": dmac,
                        "ip": ip,
                        "name": dev["name"],
                        "model": dev["shortname"],
                        "shortname": dev["shortname"],
                        "type": "uap" if is_ap else ("udm" if dev.get("isConsole") else "usw"),
                        "version": dev["version"],
                        "state": 0 if offline else 1,
                        "adopted": True,
                        "upgradable": dev["firmwareStatus"] == "updateAvailable",
                        "num_sta": sum(r["num_sta"] for r in dev.get("radios", [])),
                        "satisfaction": 52 if dev["name"] == "Conference Room AP" else 96,
                        "radio_table": [
                            {
                                "name": r["name"],
                                "radio": r["radio"],
                                "channel": "auto",
                                "ht": r["bw"],
                            }
                            for r in radios
                        ],
                        "radio_table_stats": radios,
                        "last_seen": NOW - (0 if not offline else 1800),
                    }
                )
            if "camera" in dev:
                cameras.append(
                    {
                        "id": object_id(c, 0x100 + d),
                        "modelKey": "camera",
                        "state": "DISCONNECTED" if offline else "CONNECTED",
                        "name": dev["name"],
                        "type": dev["camera"]["type"],
                        "mac": dmac.replace(":", "").upper(),
                        "isMicEnabled": False,
                        "videoMode": "default",
                        "hdrType": "auto",
                        "hasPackageCamera": False,
                        "featureFlags": {
                            "supportFullHdSnapshot": True,
                            "hasHdr": True,
                            "hasMic": True,
                            "smartDetectTypes": ["person", "vehicle", "animal"],
                        },
                    }
                )
            wrapper.append(
                {
                    "id": object_id(c, d),
                    "mac": dmac.replace(":", "").upper(),
                    "name": dev["name"],
                    "model": dev["model"],
                    "shortname": dev["shortname"],
                    "ip": ip,
                    "productLine": dev["productLine"],
                    "status": dev["status"],
                    "version": dev["version"],
                    "firmwareStatus": dev["firmwareStatus"],
                    "updateAvailable": dev.get("updateAvailable", ""),
                    "isConsole": bool(dev.get("isConsole")),
                    "isManaged": True,
                    "startupTime": None if offline else "2026-10-03T08:59:46Z",
                    "lastSeen": dev.get("lastSeen"),
                    "note": "",
                }
            )
        devices.append({"hostId": host_id, "hostName": con["hostname"], "devices": wrapper})
        sites.append(
            {
                "siteId": object_id(c, 0xFFFF),
                "hostId": host_id,
                "meta": {
                    "desc": con["name"],
                    "gatewayMac": mac(c, 0),
                    "name": "default",
                    "timezone": "Etc/UTC",
                },
                "statistics": {
                    "counts": counts,
                    "gateway": {"shortname": con["shortname"], "ipsMode": "ids"},
                    "internetIssues": [],
                    "ispInfo": {"asn": con["asn"], "name": con["isp"], "organization": con["isp"]},
                    "percentages": {"wanUptime": 100},
                    "wans": {"WAN": {"externalIp": con["wanIp"], "portUp": True, "wanUptime": 100}},
                },
                "permission": "admin",
                "isOwner": True,
            }
        )
        site_uuid = uuid(3, c, 0xFFFF)
        wifi = [
            {
                "type": "STANDARD",
                "id": uuid(4, c, 0x1000 + i),
                "name": w["name"],
                "enabled": True,
                "metadata": {"origin": "USER_DEFINED"},
                "network": {"type": "NATIVE"},
                "securityConfiguration": {
                    "type": w["security"],
                    "fastRoamingEnabled": False,
                    "pmfMode": "OPTIONAL",
                }
                | ({"passphrase": "placeholder-1"} if w["security"] != "OPEN" else {}),
                "multicastToUnicastConversionEnabled": True,
                "clientIsolationEnabled": w["security"] == "OPEN",
                "hideName": False,
                "uapsdEnabled": False,
                "channel2gLockedTo6": False,
                "dtimPeriod2gLockedTo3": False,
                "broadcastingFrequenciesGHz": w["frequencies"],
                "arpProxyEnabled": False,
                "bssTransitionEnabled": True,
                "advertiseDeviceName": False,
            }
            for i, w in enumerate(con.get("wifi", []))
        ]
        wlan_id = {w["name"]: object_id(c, 0x2000 + i) for i, w in enumerate(con.get("wifi", []))}
        clients = []
        for i, cl in enumerate(con.get("wifiClients", [])):
            ap_index, ap_mac = by_name[cl["ap"]]
            cmac = mac(c, 0x300 + i)
            clients.append(
                {
                    "_id": object_id(c, 0x300 + i),
                    "mac": cmac,
                    "hostname": cl["name"].lower().replace(" ", "-"),
                    "name": cl["name"],
                    "is_wired": False,
                    "is_guest": False,
                    "ap_mac": ap_mac,
                    "last_uplink_name": cl["ap"],
                    "essid": cl["essid"],
                    "wlanconf_id": wlan_id.get(cl["essid"], ""),
                    "radio": cl["radio"],
                    "radio_proto": "ax",
                    "channel": cl["channel"],
                    "channel_width": 20,
                    "signal": cl["signal"],
                    "rssi": cl["signal"] + 95,
                    "noise": -92,
                    "tx_rate": cl["rate"],
                    "rx_rate": cl["rate"],
                    "wifi_tx_retries_percentage": cl["retries"],
                    "tx_retries": int(cl["retries"] * 40),
                    "wifi_tx_attempts": 4000,
                    "satisfaction": cl["satisfaction"],
                    "satisfaction_real": cl["satisfaction"],
                    "satisfaction_reason": 0 if cl["satisfaction"] > 80 else 7,
                    "ip": f"198.51.100.{100 + i}",
                    "network": "Default",
                    "vlan": 1,
                    "uptime": 3600 + 120 * i,
                    "last_seen": NOW,
                    "first_seen": NOW - 86400 * 30,
                }
            )
        counts["wifiClient"] = sum(not client["is_wired"] for client in clients)
        counts["wiredClient"] = sum(client["is_wired"] for client in clients)
        counts["guestClient"] = sum(client["is_guest"] for client in clients)
        neighbors = [
            {
                "_id": object_id(c, 0x400 + i),
                "bssid": mac(c, 0x400 + i),
                "essid": n["essid"],
                "band": "ng" if n["channel"] <= 14 else "na",
                "channel": n["channel"],
                "freq": 2407 + 5 * n["channel"],
                "signal": n["signal"],
                "rssi": n["signal"] + 95,
                "noise": -95,
                "bw": 20,
                "is_rogue": False,
                "security": "WPA2-Personal (AES/CCMP)",
                "ap_mac": by_name.get("Conference Room AP", (0, mac(c, 3)))[1],
                "last_seen": NOW - 60,
            }
            for i, n in enumerate(con.get("neighbors", []))
        ]
        health = [
            {
                "subsystem": "wlan",
                "status": "warning" if neighbors else "ok",
                "num_ap": counts["wifiDevice"],
                "num_adopted": counts["wifiDevice"],
                "num_disconnected": counts["offlineWifiDevice"],
                "num_user": con["clients"]["wifi"],
                "num_guest": con["clients"]["guest"],
            },
            {
                "subsystem": "wan",
                "status": "ok",
                "wan_ip": con["wanIp"],
                "isp_name": con["isp"],
                "asn": con["asn"],
                "num_gw": 1,
                "latency": 9 + c,
            },
            {"subsystem": "lan", "status": "ok", "num_sw": 1, "num_user": con["clients"]["wired"]},
        ]
        consoles[host_id] = {
            "site": {"id": site_uuid, "internalReference": "default", "name": "Default"},
            "devices": net_devices,
            "classic_devices": classic_devices,
            "cameras": cameras,
            "wifi": wifi,
            "clients": clients,
            "neighbors": neighbors,
            "health": health,
            "rtsps": {"host": f"192.0.2.{c * 10}"},
            "firewall_policies": [
                {
                    "id": DOC_UUID,
                    "name": "Allow DNS",
                    "enabled": True,
                    "action": {"type": "ALLOW"},
                    "loggingEnabled": False,
                    "index": 10000,
                    "metadata": {"origin": "USER_DEFINED"},
                }
            ],
            "scheduletasks": [
                {
                    "_id": DOC_TASK_ID,
                    "name": "Monthly upgrades",
                    "action": "upgrade",
                    "cron_expr": "0 0 1 * *",
                    "upgrade_targets": [],
                }
            ],
            "networks": [
                {
                    "management": "GATEWAY",
                    "id": uuid(4, c, 1),
                    "name": "Default",
                    "enabled": True,
                    "vlanId": 1,
                    "metadata": {"origin": "SYSTEM_DEFINED", "configurable": True},
                    "default": True,
                },
                {
                    "management": "GATEWAY",
                    "id": uuid(4, c, 2),
                    "name": "Staff",
                    "enabled": True,
                    "vlanId": 10,
                    "metadata": {"origin": "USER_DEFINED"},
                    "default": False,
                },
            ],
        }
    return {"hosts": hosts, "sites": sites, "devices": devices, "consoles": consoles}


def envelope(data: object) -> dict:
    return {"data": data, "httpStatusCode": 200, "traceId": TRACE}


def page(data: list) -> dict:
    return {"offset": 0, "limit": 200, "count": len(data), "totalCount": len(data), "data": data}


def classic(data: list) -> dict:
    return {"meta": {"rc": "ok"}, "data": data}


def innerspace_project() -> dict:
    """A small InnerSpace project: one floor plan with a scale marker (synthetic geometry)."""
    plan = "00000000-0000-4000-8000-000000000100"
    project = "00000000-0000-4000-a000-000000000100"
    return {
        "id": project,
        "name": "Demo project",
        "plans": [{"id": plan, "name": "Ground floor", "ordering": 0}],
        "products": [],
        "wallTypes": [],
        "shapes": [
            {
                "type": "scale",
                "id": "00000000-0000-4000-8000-000000000200",
                "status": 0,
                "projectId": project,
                "planId": plan,
                "position": [{"x": 0, "y": 0, "z": 0}, {"x": 100, "y": 0, "z": 0}],
                "createdAt": "2026-10-01T00:00:00.000Z",
                "updatedAt": "2026-10-10T00:00:00.000Z",
            }
        ],
    }


def recognition_detections(kind: str, group_id: str) -> dict:
    """One page of synthetic recognition detections for a group (no biometric data)."""
    return {
        "detections": [
            {
                "id": f"00000000-0000-4000-9000-{n:012d}",
                "type": kind,
                "groupId": group_id,
                "detectedAt": (NOW - 600 * n) * 1000,
                "thumbnailId": f"00000000-0000-4000-9100-{n:012d}",
            }
            for n in range(1, 4)
        ],
        "links": {"next": None},
    }


def site_manager_object(path: str) -> dict | None:
    """Site Manager, Carrier Fabric and Mobility single-object reads (synthetic)."""
    sdwan = f"/v1/sd-wan-configs/{SDWAN_CONFIG_ID}"
    if path == sdwan:
        return envelope({"id": SDWAN_CONFIG_ID, "name": "Demo SD-WAN", "type": "hub-spoke"})
    if path == f"{sdwan}/status":
        return envelope({"id": SDWAN_CONFIG_ID, "status": "ACTIVE", "hubs": 1, "spokes": 2})
    if path == f"/v1/carrier/subscribers/{CARRIER_SUBSCRIBER_ID}":
        return envelope(
            {
                "id": CARRIER_SUBSCRIBER_ID,
                "name": "Demo subscriber",
                "status": "ACTIVE",
                "servicePlanId": CARRIER_PLAN_ID,
                "hostIds": [],
            }
        )
    if path == f"/v1/carrier/service-plans/{CARRIER_PLAN_ID}":
        return envelope(
            {
                "id": CARRIER_PLAN_ID,
                "name": "Demo 100 Mbps",
                "downstreamMbps": 100,
                "upstreamMbps": 20,
            }
        )
    for ws, dev in (
        (MOBILITY_WORKSPACE_ID, MOBILITY_DEVICE_ID),
        (DOC_UUID, DOC_UUID),
    ):
        if path == f"/v1/mobility/workspaces/{ws}/devices/{dev}":
            return envelope(
                {
                    "id": dev,
                    "name": "Demo UMR",
                    "model": "UMR-Ultra",
                    "status": "ONLINE",
                    "network": {"hostAddress": "198.51.100.1", "dhcpMode": "dhcp"},
                    "wan": {"type": "CELLULAR", "signalDbm": -85},
                }
            )
    return None


def console_route(con: dict, rest: str):
    """(status, body) for a connector path under /proxy/, or None."""
    site = con["site"]["id"]
    net = "network/integration/v1"
    simple = {
        f"{net}/info": {"applicationVersion": "10.0.160"},
        f"{net}/sites": page([con["site"]]),
        f"{net}/sites/{site}/devices": page(con["devices"]),
        f"{net}/sites/{site}/networks": page(con["networks"]),
        f"{net}/sites/{site}/wifi/broadcasts": page(con["wifi"]),
        f"{net}/sites/{site}/clients": page(
            [
                {
                    "type": "WIRELESS",
                    "id": c["_id"],
                    "name": c["name"],
                    "macAddress": c["mac"],
                    "ipAddress": c["ip"],
                    "connectedAt": "2026-10-11T05:00:00Z",
                    "uplinkDeviceId": c["ap_mac"],
                }
                for c in con["clients"]
            ]
        ),
        "network/api/s/default/stat/sta": classic(con["clients"]),
        "network/api/s/default/stat/device": classic(con["classic_devices"]),
        "network/api/s/default/stat/rogueap": classic(con["neighbors"]),
        "network/api/s/default/stat/health": classic(con["health"]),
        "network/api/s/default/rest/channelplan": classic([]),
        "network/api/s/default/rest/scheduletask": classic(con["scheduletasks"]),
        f"{net}/sites/{site}/firewall/policies": page(con["firewall_policies"]),
        "innerspace/api/project": innerspace_project(),
        "innerspace/integration/v1/project": envelope(innerspace_project()),
        "protect/integration/v1/cameras": con["cameras"],
        "protect/integration/v1/meta/info": {"applicationVersion": "6.1.70"},
    }
    if rest in simple:
        return 200, simple[rest]
    for coll, key in (
        (f"{net}/sites/{site}/devices/", "devices"),
        (f"{net}/sites/{site}/networks/", "networks"),
        (f"{net}/sites/{site}/wifi/broadcasts/", "wifi"),
        (f"{net}/sites/{site}/firewall/policies/", "firewall_policies"),
    ):
        if rest.startswith(coll):
            item_id, _, tail = rest[len(coll) :].partition("/")
            if key == "devices" and item_id == DOC_UUID and con[key]:
                item_id = con[key][0]["id"]  # the documentation's placeholder device
            for item in con[key]:
                if item["id"] == item_id:
                    if not tail:
                        return 200, item
                    if key == "devices" and tail == "statistics/latest":
                        return 200, {
                            "uptimeSec": 557462,
                            "lastHeartbeatAt": "2026-10-11T05:59:30Z",
                            "cpuUtilizationPct": 21.4,
                            "memoryUtilizationPct": 63.0,
                            "uplink": {"txRateBps": 592264, "rxRateBps": 1275512},
                        }
    m = re.fullmatch(r"network/api/s/default/rest/scheduletask/([0-9a-f]{24})", rest)
    if m:
        tasks = [t for t in con["scheduletasks"] if t["_id"] == m[1]]
        return (200, classic(tasks)) if tasks else None
    m = re.fullmatch(r"protect/api/recognition/(face|vehicle)/groups/([^/]+)/detections", rest)
    if m:
        return 200, recognition_detections(m[1], m[2])
    m = re.fullmatch(
        r"protect/integration/v1/cameras/([0-9a-f]{24})(/snapshot|/rtsps-stream)?", rest
    )
    if m:
        wanted = con["cameras"][0]["id"] if m[1] == DOC_CAMERA_ID and con["cameras"] else m[1]
        cam = next((x for x in con["cameras"] if x["id"] == wanted), None)
        if cam is None:
            return None
        if m[2] == "/snapshot":
            return 200, "SNAPSHOT"
        if m[2] == "/rtsps-stream":
            base = f"rtsps://{con['rtsps']['host']}:7441/DEMO-FAKE-STREAM-{cam['id'][-4:]}"
            return 200, {
                "high": f"{base}-high?enableSrtp",
                "medium": None,
                "low": None,
                "package": None,
            }
        return 200, cam
    return None


class Handler(BaseHTTPRequestHandler):
    state: dict = {}
    requests: list = []
    lock = threading.Lock()
    snapshot: tuple[bytes, str] = (b"", "image/jpeg")

    def log_message(self, *args):  # quiet: the demo prints its own summary
        pass

    def _send(self, status: int, body: object, content_type: str = "application/json") -> None:
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        entry = getattr(self, "entry", None)
        if entry is not None:
            entry["status"] = status
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_command(self, path: str) -> list | None:
        """Data for a Classic `cmd/<route>` POST of exactly {"cmd": <listed read>}, else None."""
        m = CONSOLE.match(path)
        c = re.fullmatch(r"network/api/s/default/cmd/([a-z]+)", m["rest"]) if m else None
        if not c or m["host"] not in self.state["consoles"]:
            return None
        try:
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}"
            )
        except ValueError:
            return None
        if not isinstance(body, dict) or set(body) != {"cmd"}:
            return None
        return CLASSIC_READ_COMMANDS.get((c[1], body["cmd"]))

    def _handle(self) -> None:
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query)
        if path == "/_demo/requests":
            with self.lock:
                return self._send(200, list(self.requests))
        with self.lock:
            self.requests.append({"method": self.command, "path": path})
            self.entry = self.requests[-1]
        if self.headers.get("X-API-KEY") != API_KEY:
            return self._send(401, {"code": "unauthorized", "message": "invalid API key"})
        if self.command == "POST" and (hit := self._read_command(path)) is not None:
            self.entry["read_post"] = True  # a listed Classic read command; nothing changes
            return self._send(200, classic(hit))
        if self.command != "GET":
            # A demo write that got this far would be visible in /_demo/requests.
            return self._send(405, {"message": "the demo mock accepts reads only"})
        s = self.state
        if path == "/v1/hosts":
            return self._send(200, envelope(s["hosts"]))
        if path.startswith("/v1/hosts/"):
            for h in s["hosts"]:
                if h["id"] == path.rsplit("/", 1)[1]:
                    return self._send(200, envelope(h))
        if (obj := site_manager_object(path)) is not None:
            return self._send(200, obj)
        if path == "/v1/sites":
            return self._send(200, envelope(s["sites"]))
        if path == "/v1/devices":
            wanted = query.get("hostIds[]")
            return self._send(
                200, envelope([w for w in s["devices"] if not wanted or w["hostId"] in wanted])
            )
        m = CONSOLE.match(path)
        if m and m["host"] in s["consoles"]:
            hit = console_route(s["consoles"][m["host"]], m["rest"])
            if hit == (200, "SNAPSHOT"):
                return self._send(200, *self.snapshot)
            if hit is not None:
                return self._send(*hit)
        return self._send(404, {"code": "not_found", "message": f"demo mock has no {path}"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    Handler.state = build(json.loads(FIXTURES.read_text()))
    Handler.snapshot = snapshot_image()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
