# README demo

`docs/assets/demo.mp4` (and `demo.gif`) is a **scripted replica of a Claude Code session**
against a **mock UniFi API with synthetic data**. No language model runs and nothing talks
to a real UniFi controller or account.

What is real: every tool call on screen is a real MCP call to this server, started over
stdio with `UNIFI_API_BASE_URL` pointed at the mock and `UNIFI_DRY_RUN=1`. Every name,
count, URL and dry-run preview shown is read from those tool results, and the mock's
request log is what proves that no write reached the API. The camera image is the JPEG
that `get_camera_snapshot` returned: `demo.py` saves those bytes and `compose.py` shows
them.

What is scripted: the four prompts, the assistant's wording, the "Thinking…" and
"Pondering…" pauses, and the session chrome (drawn by `demo.py` to look like Claude Code's
terminal UI). The image-preview panel is added after recording by `compose.py`, because
vhs records only the terminal's text layers, so an inline terminal image (sixel or iTerm
inline images) does not appear in its output.

| Scene | Tools called |
| --- | --- |
| Which sites have offline devices? | `list_sites`, `list_devices` |
| Add an isolated guest VLAN 30 at the Warehouse. | `create_network` (dry-run preview, 0 writes) |
| Show me the hallway camera and a stream link. | `list_cameras`, `get_camera_snapshot`, `get_rtsps_stream` |
| Why is the Wi-Fi slow in the conference room? | `list_active_clients_stats`, `get_client_link_diagnostics`, `list_rogue_aps`, `list_wifi_broadcasts`, `get_wifi_broadcast`, `update_wifi_broadcast` (dry-run preview, 0 writes) |

| File | What it is |
| --- | --- |
| `fixtures.json` | Invented consoles, sites, devices, Wi-Fi clients, SSIDs, neighbouring networks and cameras. Device models, firmware strings, radio fields and the status mix follow real UniFi API responses; every name is made up. |
| `mock_api.py` | A local mock of the Site Manager API and the connector paths the scenes use (Network integration, Classic `stat/*`, Protect integration). It binds `127.0.0.1` only, accepts the API key `api-key-1`, generates locally administered MACs (`02:00:5e:...`), zero-padded ids and RFC 5737 documentation IPs at load time, serves `hallway.jpg` as every camera's snapshot, refuses every write, and records each request at `GET /_demo/requests`. |
| `hallway.jpg` | The mock camera's snapshot: a stock photograph of an empty office corridor, processed to look like a camera frame (see below). |
| `make_hallway.py` | Rebuilds `hallway.jpg` from the original photograph. |
| `demo.py` | The MCP client and the replica UI. |
| `run.sh` | Starts the mock, runs `demo.py`, stops the mock. |
| `demo.tape`, `background.png` | The [vhs](https://github.com/charmbracelet/vhs) script that records the raw take into `out/`, and its window background. |
| `compose.py` | Adds the image-preview panel, trims the tail and writes `docs/assets/demo.mp4` and `demo.gif`. |

## Camera image: source and license

`hallway.jpg` is derived from the photograph
<https://unsplash.com/photos/white-hallway-with-glass-windows-5shl-NRhPyc> by Petr
(Unsplash, published 2021-09-10), used under the
[Unsplash License](https://unsplash.com/license): free for commercial and non-commercial
use, no permission or attribution required. It shows an empty corridor: no people, faces,
vehicles or logos.

`make_hallway.py` blurs every sign, plate and maker's mark in it (two exit signs and a
reflection of one, a wall sign, a room-number plate, a sticker, a planter logo), crops it to
16:9 at 1920x1080, adds a slight wide-angle bulge, flatter colour, a vignette and grain,
and burns in a camera overlay: the camera name, the mock's fixed timestamp
(2026-10-11 06:00:00) and a red DEMO label. The output carries no EXIF or other metadata.

## Reproduce

From the repository root, with [uv](https://docs.astral.sh/uv/), vhs, ffmpeg and the
JetBrains Mono font installed:

```bash
uv sync
./scripts/demo/run.sh          # watch it in your terminal (96x32 or larger)
vhs scripts/demo/demo.tape     # record the raw take into scripts/demo/out/
uv run --with pillow --with numpy python scripts/demo/compose.py   # write docs/assets/
```

`compose.py` finds the frame where the answer prints the cyan `[Image #1]` tag, shows the
saved snapshot beside the transcript from 0.25 s later for 3.2 s, and ends the video 3 s
after the last change on screen.

`DEMO_PACE=0 ./scripts/demo/run.sh` runs it without pauses. `DEMO_PORT` changes the
mock's port (default 8765). Pillow is pulled in by `uv run --with pillow` to read the
snapshot's size; it is not a dependency of the server.

## MSP demonstrations

`msp.py` creates five synthetic client sites from the existing fixtures and starts a
loopback-only mock with two synthetic keys. It runs the real server over MCP stdio.
The three prompts and narration are scripted. The script asserts the fleet results,
five dry-run previews with no mock writes, five successful mock POSTs routed across
both keys, and a read-only refusal with a server audit record and no mock request.
`msp_guard.py` rejects non-loopback sockets and DNS in the client and server
subprocesses. No existing keys are inherited. The guest broadcasts are stored only in
the temporary mock process.

From the repository root with the project dependencies, Pillow and FreeMono installed
(the default font path is `/usr/share/fonts/truetype/freefont/FreeMono.ttf`):

```bash
python scripts/demo/msp.py
python scripts/demo/msp_render.py
```

Set `MSP_FONT` and optionally `MSP_FONT_BOLD` to font file paths on other systems.
The first command writes transcripts to `scripts/demo/out/msp/`. The second turns those
transcripts into `docs/assets/msp-morning.gif`, `msp-guest.gif` and
`msp-read-only.gif`. The audit timestamp and duration are generated by the server, so
those fields change between runs.
