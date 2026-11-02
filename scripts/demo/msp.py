#!/usr/bin/env python3
"""Reproduce three scripted MSP demonstrations using only a loopback mock.

The prompts and narration are scripted; every result comes from actual MCP calls.
"""

import asyncio
import copy
import json
import os
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import mock_api
import msp_guard

msp_guard.install()
os.environ["FASTMCP_CHECK_FOR_UPDATES"] = "off"
from fastmcp import Client  # noqa: E402
from fastmcp.client.transports import StdioTransport  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = [
    "Check all client sites for offline devices and critical alerts.",
    "Preview a Guest Wi-Fi broadcast at all five client sites, then apply it to the mock.",
    "As junior staff, create a Guest Wi-Fi broadcast at Main Office.",
]
KEYS = [{"key": "demo-key-east", "label": "east"}, {"key": "demo-key-west", "label": "west"}]


class Mock(mock_api.Handler):
    requests = []

    def _handle(self):
        path = urlsplit(self.path).path
        key = self.headers.get("X-API-KEY")
        if key not in {x["key"] for x in KEYS}:
            return self._send(401, {"message": "invalid synthetic key"})
        allowed = set(self.state["keys"][key])
        self.requests.append({"method": self.command, "path": path, "key": key})
        if self.command == "GET" and path in ("/v1/hosts", "/v1/sites", "/v1/devices"):
            values = self.state[path.rsplit("/", 1)[1]]
            values = [x for x in values if x.get("hostId", x.get("id")) in allowed]
            return self._send(200, mock_api.envelope(values))
        match = mock_api.CONSOLE.match(path)
        if match and match["host"] in allowed:
            con = self.state["consoles"][match["host"]]
            if self.command == "GET":
                result = mock_api.console_route(con, match["rest"])
                if result:
                    return self._send(*result)
            if self.command == "POST" and match["rest"] == (
                "network/integration/v1/sites/{}/wifi/broadcasts".format(con["site"]["id"])
            ):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                con["wifi"].append(body)
                return self._send(200, body)
        return self._send(404, {"message": "mock route not found"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


def setup_mock():
    fixtures = json.loads(mock_api.FIXTURES.read_text())
    for name, host in [("Clinic", "clinic-gw"), ("Library", "library-gw")]:
        clone = copy.deepcopy(fixtures["consoles"][0])
        clone.update(name=name, hostname=host)
        fixtures["consoles"].append(clone)
    state = mock_api.build(fixtures)
    state["sites"][1]["statistics"]["counts"]["criticalNotification"] = 2
    for con in state["consoles"].values():
        con["networks"][1].update(name="Guest VLAN", vlanId=30)
    ids = [host["id"] for host in state["hosts"]]
    state["keys"] = {"demo-key-east": ids[:3], "demo-key-west": ids[3:]}
    Mock.state = state
    Mock.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def environment(port, **settings):
    # An explicit minimal environment prevents real keys and settings from leaking in.
    return {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": f"{ROOT / 'src'}:{ROOT / 'scripts/demo'}",
        "UNIFI_API_BASE_URL": f"http://127.0.0.1:{port}",
        "UNIFI_API_KEYS": json.dumps(KEYS),
        "UNIFI_TOOL_MODE": "full",
        "UNIFI_LOG_LEVEL": "ERROR",
        "FASTMCP_CHECK_FOR_UPDATES": "off",
        "FASTMCP_SHOW_SERVER_BANNER": "false",
        **settings,
    }


def transport(env):
    return StdioTransport(
        command=sys.executable,
        args=[
            "-c",
            "import msp_guard; msp_guard.install(); "
            "from unifi_fabric.entrypoint import main; main()",
        ],
        env=env,
    )


async def call(client, name, args):
    result = await client.call_tool(name, args)
    return (
        result.structured_content
        if result.structured_content is not None
        else json.loads(result.content[0].text)
    )


async def run():
    server = setup_mock()
    port = server.server_address[1]
    scenes = []
    try:
        async with Client(transport(environment(port))) as client:
            sites = await call(client, "list_sites", {})
            devices = await call(client, "list_devices", {})
            names = {s["hostId"]: s["meta"]["desc"] for s in sites["data"]}
            offline = [
                (names[w["hostId"]], d["name"])
                for w in devices["data"]
                for d in w["devices"]
                if d["status"] != "online"
            ]
            alerts = [
                (s["meta"]["desc"], s["statistics"]["counts"]["criticalNotification"])
                for s in sites["data"]
                if s["statistics"]["counts"]["criticalNotification"]
            ]
            if not (len(names) == 5 and offline and (alerts == [("Warehouse", 2)])):
                raise AssertionError(
                    "Morning check did not reconcile five sites, offline devices and alert counts"
                )
            scenes.append(
                [
                    PROMPTS[0],
                    "MCP: list_sites + list_devices",
                    f"{len(names)} synthetic client sites checked",
                    *[f"Offline: {site} / {dev}" for site, dev in offline],
                    *[f"Critical notifications: {site} / {count}" for site, count in alerts],
                ]
            )
        hosts = [h["reportedState"]["hostname"] for h in Mock.state["hosts"]]
        broadcast = {
            "type": "STANDARD",
            "name": "Guest",
            "enabled": True,
            "network": {"type": "SPECIFIC", "networkId": ""},
            "securityConfiguration": {"type": "OPEN"},
            "clientIsolationEnabled": True,
            "broadcastingFrequenciesGHz": [2.4, 5],
        }

        # Each synthetic site has its own network UUID.
        async def rollout(client):
            results = []
            for host, con in zip(hosts, Mock.state["consoles"].values(), strict=True):
                body = copy.deepcopy(broadcast)
                body["network"]["networkId"] = con["networks"][1]["id"]
                results.append(
                    await call(
                        client,
                        "create_wifi_broadcast",
                        {"host": host, "site": "Default", "broadcast": body},
                    )
                )
            return results

        before = len(Mock.requests)
        async with Client(transport(environment(port, UNIFI_DRY_RUN="1"))) as client:
            previews = await rollout(client)
        if not (
            len(previews) == 5
            and all(p["status"] == "dry_run" and (not p["sent"]) for p in previews)
        ):
            raise AssertionError("The five rollout calls did not all return dry-run previews")
        if not (not [r for r in Mock.requests[before:] if r["method"] != "GET"]):
            raise AssertionError("A dry-run write reached the mock")
        before = len(Mock.requests)
        async with Client(transport(environment(port))) as client:
            applied = await rollout(client)
        writes = [r for r in Mock.requests[before:] if r["method"] == "POST"]
        if not (
            len(applied) == len(writes) == 5
            and {r["key"] for r in writes} == {x["key"] for x in KEYS}
        ):
            raise AssertionError(
                "Applied writes did not cover five sites across both synthetic keys"
            )
        if not (
            {mock_api.CONSOLE.match(r["path"])["host"] for r in writes}
            == set(Mock.state["consoles"])
        ):
            raise AssertionError("Applied writes did not cover every mock console")
        if not (
            all(
                mock_api.CONSOLE.match(r["path"])["host"] in Mock.state["keys"][r["key"]]
                for r in writes
            )
        ):
            raise AssertionError("An applied write used a key that does not own its mock console")
        scenes.append(
            [
                PROMPTS[1],
                "MCP: create_wifi_broadcast x 5",
                "Preview: five requests, zero writes sent",
                "Apply: five writes accepted by MOCK ONLY",
                *[f"Applied: {h}" for h in hosts],
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            before = len(Mock.requests)
            async with Client(
                transport(
                    environment(
                        port,
                        UNIFI_READ_ONLY="1",
                        UNIFI_AUDIT_LOG=str(audit),
                        UNIFI_AUDIT_LOG_FORMAT="json",
                    )
                )
            ) as client:
                try:
                    await call(
                        client,
                        "create_wifi_broadcast",
                        {"host": hosts[0], "site": "Default", "broadcast": broadcast},
                    )
                except Exception as exc:
                    if "UNIFI_READ_ONLY" not in str(exc):
                        raise AssertionError(str(exc)) from exc
                else:
                    raise AssertionError("write was not refused")
            records = [json.loads(line) for line in audit.read_text().splitlines()]
            if not (len(records) == 1 and records[0]["outcome"] == "refused"):
                raise AssertionError("Read-only refusal did not produce one refused audit record")
            if not (len(Mock.requests) == before):
                raise AssertionError("A refused write contacted the mock")
            line = audit.read_text().strip()
            scenes.append(
                [
                    PROMPTS[2],
                    "MCP: create_wifi_broadcast",
                    "Refused: UNIFI_READ_ONLY=1",
                    "No request reached the mock",
                    "Actual server audit record:",
                    line,
                ]
            )
        out = ROOT / "scripts/demo/out/msp"
        out.mkdir(parents=True, exist_ok=True)
        (out / "requests.json").write_text(json.dumps(Mock.requests, indent=2) + "\n")
        for index, scene in enumerate(scenes, 1):
            (out / f"scene-{index}.txt").write_text("\n".join(scene) + "\n")
            print("\n".join(scene), "\n")
        print("PASS: all MCP results, routing, previews, writes and refusal asserted")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    asyncio.run(run())
