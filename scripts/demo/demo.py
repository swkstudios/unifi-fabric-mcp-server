#!/usr/bin/env python3
"""Scripted README demo, drawn as a replica of a Claude Code session.

The user prompts and the assistant's wording are scripted: no language model runs.
Every tool call shown is a real MCP call to the real server (started over stdio with
UNIFI_API_BASE_URL pointed at mock_api.py and UNIFI_DRY_RUN=1), and every name, count,
URL and preview on screen is read from those tool results. The camera image is the
JPEG the server returned from get_camera_snapshot; a terminal cannot show it in the
recording, so compose.py overlays those same bytes as a preview panel afterwards, keyed
on the cyan "[Image #1]" tag this script prints.
See README.md in this directory to reproduce the recording.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import shlex
import shutil
import sys
import time
import urllib.request

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from rich.box import ROUNDED, SQUARE
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

MOCK = os.environ.get("DEMO_MOCK_URL", "http://127.0.0.1:8765")
SERVER = shlex.split(os.environ.get("DEMO_SERVER_CMD", "unifi-fabric-mcp"))
PACE = float(os.environ.get("DEMO_PACE", "1"))  # 0 = no pauses (for a quick check)
SIZE = shutil.get_terminal_size((100, 32))
WIDTH, HEIGHT = SIZE.columns, SIZE.lines

# Claude Code dark-theme colours.
ORANGE, GREY, DIM, WHITE = "#d77757", "rgb(153,153,153)", "#6b6b6b", "#e6e6e6"
GREEN, RED, AMBER, BLUE = "#4eba65", "#ff6b80", "#ffc107", "#b1b9f9"
IMAGE_TAG = "#00d7ff"  # used only for "[Image #1]": compose.py finds the frame by this colour
SPIN = "·✢✳✶✻✽✻✶✳✢"

render = Console(
    width=WIDTH, color_system="truecolor", highlight=False, emoji=False, legacy_windows=False
)


def lines_of(renderable) -> list[str]:
    """Render to ANSI lines at the terminal width."""
    with render.capture() as cap:
        render.print(renderable, end="")
    out = cap.get().split("\n")
    while len(out) > 1 and out[-1] == "":
        out.pop()  # tables and grids end with a newline of their own
    return out


class Screen:
    """Full-frame redraws: transcript on top, Claude Code style input box at the bottom."""

    def __init__(self) -> None:
        self.header = lines_of(
            Panel(
                Text.assemble(
                    ("✻ ", ORANGE),
                    ("UniFi Fabric MCP Server", f"bold {WHITE}"),
                    ("  ·  connected as MCP server ", GREY),
                    ("unifi-fabric", BLUE),
                    "\n",
                    (
                        "  Scripted replica of a Claude Code session · mock UniFi API · "
                        "synthetic data",
                        DIM,
                    ),
                ),
                box=ROUNDED,
                border_style=ORANGE,
                padding=(0, 1),
                expand=False,
            )
        ) + [""]
        self.body: list[str] = []
        self.typed = ""
        self.spinner: str | None = None
        self.tick = 0

    def add(self, renderable) -> None:
        self.body += lines_of(renderable)
        self.draw()

    def reset(self) -> None:
        self.body = []
        self.draw()

    def draw(self) -> None:
        rule = Text("─" * WIDTH, style=DIM)
        spin = (
            Text.assemble(
                (SPIN[self.tick % len(SPIN)] + " ", ORANGE),
                (self.spinner + "…", ORANGE),
                ("  (esc to interrupt)", DIM),
            )
            if self.spinner
            else Text("")
        )
        prompt = Text.assemble(
            ("❯ ", WHITE), (self.typed, WHITE), ("█" if self.spinner is None else "", GREY)
        )
        status = Text.assemble(
            ("  ⏵⏵ ", AMBER),
            ("UNIFI_DRY_RUN=1", AMBER),
            (" · writes return a preview · ", DIM),
            ("unifi-fabric ✓", GREEN),
        )
        bottom = [
            *lines_of(spin),
            *lines_of(rule),
            *lines_of(prompt),
            *lines_of(rule),
            *lines_of(status),
        ]
        room = HEIGHT - len(self.header) - len(bottom)
        body = self.body[-room:] if room > 0 else []
        frame = self.header + body + [""] * (room - len(body)) + bottom
        sys.stdout.write(
            "\x1b[H" + "\n".join(line + "\x1b[K" for line in frame[:HEIGHT]) + "\x1b[J"
        )
        sys.stdout.flush()

    def wait(self, seconds: float) -> None:
        end = time.monotonic() + seconds * PACE
        while time.monotonic() < end:
            if self.spinner:
                self.tick += 1
                self.draw()
            time.sleep(0.09)

    def think(self, verb: str, seconds: float) -> None:
        """Claude Code's spinner line while the model thinks, before tools or an answer."""
        self.spinner = verb
        self.wait(seconds)
        self.spinner = None
        self.draw()

    def user(self, prompt: str) -> None:
        for ch in prompt:
            self.typed += ch
            self.draw()
            time.sleep(0.045 * PACE)
        self.wait(0.25)
        self.typed = ""
        self.add(Text.assemble(("❯ ", GREY), (prompt, f"bold {WHITE}"), style="on rgb(55,55,55)"))
        self.add(Text(""))

    def say(self, *parts, more: bool = False) -> None:
        self.add(Text(""))
        for i, part in enumerate(parts):
            self.add(
                hanging(
                    "● " if i == 0 else "  ",
                    WHITE,
                    part if not isinstance(part, str) else Text(part, WHITE),
                )
            )
            self.wait(0.15)
        if not more:
            self.add(Text(""))


class Session:
    def __init__(self, client: Client, screen: Screen) -> None:
        self.client, self.screen = client, screen

    async def tool(
        self, name: str, args: dict, summary, shown_args: str | None = None, min_s: float = 0.85
    ):
        s = self.screen
        label = (
            shown_args
            if shown_args is not None
            else ", ".join(f"{k}: {json.dumps(v)}" for k, v in args.items())
        )

        def call_line(bullet: str) -> Text:
            line = Text.assemble(
                ("● ", bullet),
                ("unifi-fabric - ", WHITE),
                (name, f"bold {WHITE}"),
                (" (MCP)", GREY),
                (f"({label})", GREY),
            )
            line.truncate(
                WIDTH - 1, overflow="ellipsis"
            )  # one line, as Claude Code truncates long arguments
            return line

        s.add(call_line(GREY))  # grey while running, green once the result is back
        s.spinner = "Calling unifi-fabric"
        started = time.monotonic()
        result = await self.client.call_tool(name, args)
        data = (
            result.structured_content
            if result.structured_content is not None
            else json.loads(result.content[0].text)
        )
        while time.monotonic() - started < min_s * PACE:
            s.wait(0.09)
        s.spinner = None
        s.body[-1] = lines_of(call_line(GREEN))[0]
        text = summary(data) if callable(summary) else summary
        for i, line in enumerate(text if isinstance(text, list) else [text]):
            s.add(
                hanging(
                    "  ⎿  " if i == 0 else "     ",
                    GREY,
                    line if isinstance(line, Text) else Text(line, GREY),
                )
            )
        return data


def hanging(prefix: str, style: str, body) -> Table:
    """A prefix column with the body wrapped beside it, as Claude Code indents its lines."""
    grid = Table.grid(padding=0)
    grid.add_column(width=len(prefix), no_wrap=True)
    grid.add_column()
    grid.add_row(Text(prefix, style), body)
    return grid


def requests_seen() -> list[dict]:
    with urllib.request.urlopen(f"{MOCK}/_demo/requests") as resp:
        return json.load(resp)


def table(headers: list[str]) -> Table:
    t = Table(
        box=SQUARE, border_style=DIM, header_style=f"bold {WHITE}", pad_edge=True, expand=False
    )
    for h in headers:
        t.add_column(h)
    return t


async def main() -> None:
    sys.stdout.write("\x1b[?25l\x1b[2J")
    screen = Screen()
    screen.draw()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "UNIFI_API_BASE_URL": MOCK,
        "UNIFI_API_KEY": "api-key-1",
        "UNIFI_DRY_RUN": "1",
        "UNIFI_TOOL_MODE": "full",
        "UNIFI_LOG_LEVEL": "ERROR",
    }
    log = open(os.devnull, "w")  # keep the server banner and logs off screen
    async with Client(
        StdioTransport(command=SERVER[0], args=SERVER[1:], env=env, log_file=log)
    ) as client:
        cc = Session(client, screen)
        screen.wait(2.6)

        # 1. A fleet-wide read.
        screen.user("Which sites have offline devices?")
        screen.think("Thinking", 1.8)
        sites = await cc.tool("list_sites", {}, lambda d: f"{d['_count']} sites")
        devs = await cc.tool(
            "list_devices",
            {},
            lambda d: f"{d['_count']} devices on {d['_consoleCount']} consoles",
        )
        site_of = {s["hostId"]: s["meta"]["desc"] for s in sites["data"]}
        flat = [(site_of[w["hostId"]], d) for w in devs["data"] for d in w["devices"]]
        off = [(site, d) for site, d in flat if d["status"] != "online"]
        upd = [d for _, d in flat if d["firmwareStatus"] == "updateAvailable"]
        t = table(["Site", "Device", "Model", "Status"])
        for site, d in off:
            t.add_row(
                site, d["name"], d["model"], Text(f"offline since {d['lastSeen'][11:16]} UTC", RED)
            )
        for d in upd:
            t.add_row(
                next(s for s, x in flat if x is d),
                d["name"],
                d["model"],
                Text(f"update {d['updateAvailable']}", AMBER),
            )
        screen.think("Pondering", 1.6)
        healthy = sorted({s["meta"]["desc"] for s in sites["data"]} - {s for s, _ in off})
        screen.say(
            f"{len({s for s, _ in off})} of {len(sites['data'])} sites have an offline AP. "
            f"{', '.join(healthy)} is all online.",
            t,
        )
        screen.wait(6.0)
        screen.reset()
        screen.wait(0.5)

        # 2. A write, previewed under UNIFI_DRY_RUN=1.
        before = len(requests_seen())
        screen.user("Add an isolated guest VLAN 30 at the Warehouse.")
        screen.think("Thinking", 1.8)
        guest = {
            "management": "GATEWAY",
            "name": "Guest",
            "vlanId": 30,
            "enabled": True,
            "internetAccessEnabled": True,
            "isolationEnabled": True,
            "cellularBackupEnabled": False,
            "ipv4Configuration": {"hostIpAddress": "192.0.2.1", "prefixLength": 24},
        }
        prev = await cc.tool(
            "create_network",
            {"host": "warehouse-gw", "site": "Default", "network_config": guest},
            lambda d: [
                Text("◆ " + d["message"], AMBER),
                f"{d['preview']['method']} …/sites/{{siteId}}/networks",
            ],
            shown_args='host: "warehouse-gw", name: "Guest", vlanId: 30, isolationEnabled: true',
        )
        writes = [r for r in requests_seen()[before:] if r["method"] != "GET"]
        screen.think("Pondering", 1.6)
        screen.say(
            f"Dry-run preview only: {prev['preview']['method']} would create 'Guest' "
            "on VLAN 30, isolated. "
            f"{len(writes)} writes reached the API."
        )
        screen.wait(5.0)
        screen.reset()
        screen.wait(0.5)

        # 3. UniFi Protect: snapshot and stream link.
        screen.user("Show me the hallway camera and a stream link.")
        screen.think("Thinking", 1.8)
        cams = await cc.tool(
            "list_cameras", {"host": "main-office-gw"}, lambda d: f"{d['_count']} cameras"
        )
        cam = next(c for c in cams["result"] if c["name"] == "Hallway")
        from PIL import Image

        def snap_line(d: dict) -> str:
            w, h = Image.open(io.BytesIO(base64.b64decode(d["image_base64"]))).size
            return f"{d['content_type']} · {w}×{h} · {d['size_bytes'] // 1024} KB (base64)"

        snap = await cc.tool(
            "get_camera_snapshot",
            {"host": "main-office-gw", "camera_id": cam["id"]},
            snap_line,
            shown_args=f'host: "main-office-gw", camera_id: "…{cam["id"][-6:]}"',
        )
        rtsps = await cc.tool(
            "get_rtsps_stream",
            {"host": "main-office-gw", "camera_id": cam["id"]},
            lambda d: "high: " + d["high"].split("?")[0],
            shown_args=f'host: "main-office-gw", camera_id: "…{cam["id"][-6:]}"',
        )
        jpeg = base64.b64decode(snap["image_base64"])
        if out := os.environ.get("DEMO_SNAPSHOT_OUT"):  # compose.py shows exactly these bytes
            with open(out, "wb") as fh:
                fh.write(jpeg)
        w, h = Image.open(io.BytesIO(jpeg)).size
        screen.think("Pondering", 1.6)
        screen.say(
            f"{cam['name']} ({cam['type']}) is {cam['state'].lower()}. Current frame, {w}×{h}:",
            Text("[Image #1]", f"bold {IMAGE_TAG}"),
            more=True,
        )
        screen.wait(3.8)  # compose.py shows the image beside the transcript here
        screen.add(hanging("  ", WHITE, Text.assemble(("Stream: ", WHITE), (rtsps["high"], BLUE))))
        screen.add(Text(""))
        screen.wait(3.0)
        screen.reset()
        screen.wait(0.5)

        # 4. Multi-tool diagnosis, then a dry-run fix.
        before = len(requests_seen())
        screen.user("Why is the Wi-Fi slow in the conference room?")
        screen.think("Thinking", 1.8)
        here = {"host": "main-office-gw", "site": "Default"}
        sta = await cc.tool(
            "list_active_clients_stats",
            here,
            lambda d: f"{len(d['data'])} Wi-Fi clients",
            shown_args='host: "main-office-gw", site: "Default"',
        )
        conf = [c for c in sta["data"] if c["last_uplink_name"] == "Conference Room AP"]
        worst = min(conf, key=lambda c: c["satisfaction"])
        diag = (
            await cc.tool(
                "get_client_link_diagnostics",
                {**here, "client_id": worst["mac"]},
                lambda d: (
                    lambda c: (
                        f"{c['name']}: {c['signal']} dBm, "
                        f"{c['wifi_tx_retries_percentage']:.0f}% retries, 2.4 GHz ch {c['channel']}"
                    )
                )(d["data"][0]),
                shown_args=f'site: "Default", client_id: "{worst["mac"]}"',
            )
        )["data"][0]
        rogue = await cc.tool(
            "list_rogue_aps",
            here,
            lambda d: (
                f"{sum(1 for n in d['data'] if n['channel'] == diag['channel'])} "
                f"neighbouring networks on channel {diag['channel']}"
            ),
            shown_args='host: "main-office-gw", site: "Default"',
        )
        wl = await cc.tool(
            "list_wifi_broadcasts",
            here,
            lambda d: ", ".join(
                f"{x['name']} {'/'.join(str(f) for f in x['broadcastingFrequenciesGHz'])} GHz"
                for x in d["data"]
            ),
            shown_args='host: "main-office-gw", site: "Default"',
        )
        office = next(x for x in wl["data"] if x["name"] == worst["essid"])
        cur = await cc.tool(
            "get_wifi_broadcast",
            {**here, "broadcast_id": office["id"]},
            lambda d: (
                f"{d['name']}: {d['securityConfiguration']['type']}, "
                f"{d['broadcastingFrequenciesGHz']} GHz"
            ),
            shown_args=f'site: "Default", broadcast_id: "…{office["id"][-8:]}"',
        )
        body = {k: v for k, v in cur.items() if k not in ("id", "metadata")}
        body["broadcastingFrequenciesGHz"] = [2.4, 5, 6]
        await cc.tool(
            "update_wifi_broadcast",
            {**here, "broadcast_id": office["id"], "broadcast": body},
            lambda d: [
                Text("◆ " + d["message"], AMBER),
                f"broadcastingFrequenciesGHz {cur['broadcastingFrequenciesGHz']} → "
                f"{d['preview']['body']['broadcastingFrequenciesGHz']}",
            ],
            shown_args=f'broadcast_id: "…{office["id"][-8:]}", broadcast: {{…}}',
        )
        writes = [r for r in requests_seen()[before:] if r["method"] != "GET"]
        neighbours = sum(1 for n in rogue["data"] if n["channel"] == diag["channel"])
        screen.think("Pondering", 1.6)
        screen.say(
            f"'{office['name']}' only broadcasts on 2.4 GHz, and channel {diag['channel']} "
            "there is shared with "
            f"{neighbours} neighbouring networks, so {len(conf)} conference clients see "
            f"~{round(sum(c['wifi_tx_retries_percentage'] for c in conf) / len(conf))}% retries.",
            f"Fix previewed: add 5 and 6 GHz to '{office['name']}'. "
            f"Dry run, {len(writes)} writes sent.",
        )
        screen.wait(float(os.environ.get("DEMO_FINAL_HOLD", "30")))  # the recording cuts first
    sys.stdout.write("\x1b[?25h")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()
