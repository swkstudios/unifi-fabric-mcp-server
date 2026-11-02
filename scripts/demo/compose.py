#!/usr/bin/env python3
"""Finish the recording: add the camera image as a preview panel, trim, encode.

vhs captures xterm.js's text layers only, so an inline terminal image (sixel or iTerm
inline images) never reaches the recording. Instead, demo.py prints a cyan "[Image #1]"
tag when the answer shows the snapshot, and writes the exact JPEG the server returned
to out/snapshot.jpg. This script finds the first frame with that tag, overlays those
bytes as a preview panel beside the transcript for about 3 s, trims the static tail
to a 3 s hold, and writes docs/assets/demo.mp4 and demo.gif.

    vhs scripts/demo/demo.tape
    uv run --with pillow --with numpy python scripts/demo/compose.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
ASSETS = HERE.parent.parent / "docs" / "assets"
W, H, FPS = 1300, 960, 20
PANEL_DELAY, PANEL_SECONDS, FADE = 0.25, 3.2, 0.15
FINAL_HOLD = 3.0
TAG_RGB = (0x00, 0xD7, 0xFF)  # IMAGE_TAG in demo.py


def frames(path: Path):
    """Yield (index, RGB array) for every frame of the raw recording at FPS."""
    cmd = ["ffmpeg", "-v", "error", "-i", str(path), "-vf", f"fps={FPS}"]
    cmd += ["-f", "rawvideo", "-pix_fmt", "rgb24", "-"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
        i, pipe = 0, proc.stdout
        while pipe and (buf := pipe.read(W * H * 3)):
            yield i, np.frombuffer(buf, np.uint8).reshape(H, W, 3)
            i += 1


def scan(path: Path) -> tuple[float, tuple[int, int, int, int], float]:
    """Seconds to the first frame showing the tag (and its bbox), and to the last change."""
    first, bbox, last, prev = -1.0, (0, 0, 0, 0), 0.0, None
    for i, f in frames(path):
        if first < 0:
            d = np.abs(f.astype(np.int16) - np.array(TAG_RGB, np.int16)).sum(axis=2)
            ys, xs = np.nonzero(d < 60)
            if len(xs) > 40:
                first = i / FPS
                bbox = (int(xs.min()), int(ys.min()), int(xs.max()), int(ys.max()))
        # Count clearly changed pixels, so encoder noise in the MP4 is not a change.
        if prev is not None and (np.abs(f.astype(np.int16) - prev).max(axis=2) > 40).sum() > 20:
            last = (i + 1) / FPS
        prev = f.astype(np.int16)
    if first < 0:
        raise SystemExit("no [Image #1] tag in the recording; did demo.py change?")
    return first, bbox, last


def font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("JetBrainsMono-Regular.ttf", "DejaVuSansMono.ttf"):
        for base in (Path.home() / "Library/Fonts", Path("/usr/share/fonts/truetype/dejavu")):
            if (base / name).exists():
                return ImageFont.truetype(str(base / name), size)
    return ImageFont.load_default(size=size)


SHADOW = 24  # transparent margin around the panel for its drop shadow


def panel(jpeg: Path, dest: Path) -> tuple[int, int]:
    """A floating image-preview window around the snapshot; returns its size."""
    img = Image.open(jpeg).convert("RGB")
    title = f"[Image #1]  {img.width}×{img.height} · image/jpeg · from get_camera_snapshot"
    img = img.resize((640, 360), Image.LANCZOS)
    bar, pad = 32, 8
    pw, ph = img.width + 2 * pad, img.height + bar + pad
    out = Image.new("RGBA", (pw + 2 * SHADOW, ph + 2 * SHADOW), (0, 0, 0, 0))
    shadow = Image.new("L", out.size, 0)
    ImageDraw.Draw(shadow).rounded_rectangle(
        (SHADOW, SHADOW + 6, SHADOW + pw, SHADOW + ph + 6), radius=12, fill=170
    )
    out.putalpha(shadow.filter(ImageFilter.GaussianBlur(12)))
    d = ImageDraw.Draw(out)
    box = (SHADOW, SHADOW, SHADOW + pw - 1, SHADOW + ph - 1)
    d.rounded_rectangle(box, radius=10, fill=(24, 24, 37, 255), outline=(88, 91, 112, 255))
    for k, rgb in enumerate(((255, 95, 87), (254, 188, 46), (40, 200, 64))):
        cx = SHADOW + 18 + k * 18
        d.ellipse((cx - 5, SHADOW + 11, cx + 5, SHADOW + 21), fill=(*rgb, 255))
    d.text((SHADOW + 78, SHADOW + 7), title, font=font(14), fill=(186, 194, 222, 255))
    out.paste(img, (SHADOW + pad, SHADOW + bar))
    out.save(dest)
    return out.size


def encode(src: Path, png: Path, at: tuple[int, int], t0: float, end: float, dest: Path) -> None:
    fade_out = PANEL_SECONDS - FADE
    graph = (
        f"[1:v]format=rgba,fade=in:st=0:d={FADE}:alpha=1,"
        f"fade=out:st={fade_out}:d={FADE}:alpha=1,setpts=PTS-STARTPTS+{t0}/TB[p];"
        f"[0:v]fps={FPS}[b];"
        f"[b][p]overlay={at[0]}:{at[1]}:eof_action=pass:"
        f"enable='between(t,{t0},{t0 + PANEL_SECONDS})'"
    )
    if dest.suffix == ".gif":
        graph += ",split[a][c];[a]palettegen=stats_mode=diff:max_colors=256[pal];"
        graph += "[c][pal]paletteuse=dither=none:diff_mode=rectangle"
        codec = ["-loop", "0"]
    else:
        codec = ["-c:v", "libx264", "-crf", "20", "-preset", "slow", "-pix_fmt", "yuv420p"]
        codec += ["-movflags", "+faststart"]
    cmd = ["ffmpeg", "-v", "error", "-y", "-i", str(src)]
    cmd += ["-loop", "1", "-framerate", str(FPS), "-t", str(PANEL_SECONDS), "-i", str(png)]
    cmd += ["-filter_complex", graph, "-t", f"{end:.2f}", "-an", *codec, str(dest)]
    subprocess.run(cmd, check=True)


def main() -> None:
    t_tag, bbox, t_last = scan(OUT / "raw.mp4")
    end = t_last + FINAL_HOLD
    pw, ph = panel(OUT / "snapshot.jpg", OUT / "panel.png")
    # Beside the tag: to its right, with its top just below the tag's line.
    at = (bbox[2] + 90 - SHADOW, bbox[3] + 8 - SHADOW)
    if at[1] + ph - SHADOW > H - 40:
        raise SystemExit("the panel would leave the window; did the layout change?")
    t0 = round(t_tag + PANEL_DELAY, 2)
    ASSETS.mkdir(parents=True, exist_ok=True)
    encode(OUT / "raw.mp4", OUT / "panel.png", at, t0, end, ASSETS / "demo.mp4")
    encode(OUT / "raw.gif", OUT / "panel.png", at, t0, end, ASSETS / "demo.gif")
    print(json.dumps({"tag_s": t_tag, "panel_s": [t0, t0 + PANEL_SECONDS], "end_s": end}))


if __name__ == "__main__":
    main()
