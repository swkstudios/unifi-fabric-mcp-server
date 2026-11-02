#!/usr/bin/env python3
"""Render verified MSP transcripts as short animated GIFs with Pillow."""

import os
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

root = Path(__file__).resolve().parents[2]
font_path = os.environ.get("MSP_FONT", "/usr/share/fonts/truetype/freefont/FreeMono.ttf")
font = ImageFont.truetype(font_path, 20)
bold = ImageFont.truetype(os.environ.get("MSP_FONT_BOLD", font_path), 22)
titles = ["Morning check", "Guest Wi-Fi rollout", "Junior staff access"]
names = ["msp-morning.gif", "msp-guest.gif", "msp-read-only.gif"]
for number, (title, name) in enumerate(zip(titles, names, strict=True), 1):
    lines = (root / f"scripts/demo/out/msp/scene-{number}.txt").read_text().splitlines()
    frames = []
    for count in range(1, len(lines) + 1):
        frame = Image.new("RGB", (1200, 660), (16, 25, 35))
        draw = ImageDraw.Draw(frame)
        draw.rounded_rectangle(
            (25, 25, 1175, 635), radius=14, fill=(25, 40, 53), outline="#3d5665", width=2
        )
        draw.text((52, 48), "UNIFI FABRIC MCP  /  " + title, font=bold, fill="#8fe4ce")
        draw.text(
            (52, 85),
            "SCRIPTED SESSION  |  SYNTHETIC DATA  |  LOOPBACK MOCK",
            font=font,
            fill="#9caeb8",
        )
        y = 140
        for i, line in enumerate(lines[:count]):
            prefix = "PROMPT: " if i == 0 else ""
            if line.startswith("{"):
                line = line.replace(",", ", ")
            for part in textwrap.wrap(prefix + line, width=88, break_long_words=True):
                draw.text((52, y), part, font=font, fill="#ffffff" if i == 0 else "#cce0e6")
                y += 29
            y += 8 if i < 2 else 0
        frames.append(frame)
    frames[0].save(
        root / "docs/assets" / name,
        save_all=True,
        append_images=frames[1:],
        duration=[1100] * (len(frames) - 1) + [4500],
        loop=0,
        optimize=True,
    )
    print(name, len(frames), "frames")
