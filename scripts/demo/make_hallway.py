#!/usr/bin/env python3
"""Build hallway.jpg, the mock camera's snapshot, from the source photograph.

Source: https://unsplash.com/photos/white-hallway-with-glass-windows-5shl-NRhPyc
(Unsplash License; see README.md). Download the original, then:

    uv run --with pillow --with numpy python scripts/demo/make_hallway.py original.jpg

It blurs every sign, plate and maker's mark, crops to 16:9, adds a slight wide-angle
bulge, softens and desaturates the colour, adds a vignette and sensor grain, and burns in
a camera overlay (name, timestamp, DEMO). The output is committed; this script is only
needed to rebuild it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

HERE = Path(__file__).resolve().parent
# Regions in the 5472x3648 original that hold text or marks: both exit signs and the
# exit sign's reflection, a small wall sign, a room-number plate, a sticker, a planter logo.
REDACT = [
    (1540, 650, 1790, 820),
    (1670, 1150, 1795, 1215),
    (3000, 730, 3130, 830),
    (1815, 1480, 1865, 1530),
    (2495, 1060, 2555, 1150),
    (5380, 920, 5472, 1030),
    (0, 3330, 90, 3460),
    (770, 2680, 900, 2740),
]
STAMP = "2026-10-11  06:00:00"  # the mock's fixed clock (NOW in mock_api.py)


def font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("JetBrainsMono-Bold.ttf", "DejaVuSansMono-Bold.ttf"):
        for base in (Path.home() / "Library/Fonts", Path("/usr/share/fonts/truetype/dejavu")):
            if (base / name).exists():
                return ImageFont.truetype(str(base / name), size)
    return ImageFont.load_default(size=size)


def main(src: str) -> None:
    img = Image.open(src).convert("RGB")
    for box in REDACT:
        img.paste(img.crop(box).filter(ImageFilter.GaussianBlur(26)), box)

    w, h = img.size  # 16:9 crop that keeps the ceiling run and the far door
    ch = w * 9 // 16
    img = img.crop((0, 250, w, 250 + ch)).resize((1920, 1080), Image.LANCZOS)

    # Slight barrel distortion, as from a wide-angle dome lens.
    a = np.asarray(img).astype(np.float32)
    H, W = a.shape[:2]
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    nx, ny = (xx - W / 2) / (W / 2), (yy - H / 2) / (W / 2)
    r2 = nx * nx + ny * ny
    k = 0.06
    scale = (1 + k * r2) / (1 + k * 0.6)  # zoom slightly so the corners stay filled
    fx = np.clip(nx * scale * (W / 2) + W / 2, 0, W - 1.001)
    fy = np.clip(ny * scale * (W / 2) + H / 2, 0, H - 1.001)
    x0, y0 = fx.astype(np.int32), fy.astype(np.int32)
    tx, ty = (fx - x0)[..., None], (fy - y0)[..., None]
    a = (
        a[y0, x0] * (1 - tx) * (1 - ty)
        + a[y0, x0 + 1] * tx * (1 - ty)
        + a[y0 + 1, x0] * (1 - tx) * ty
        + a[y0 + 1, x0 + 1] * tx * ty
    )  # bilinear sampling

    # Camera colour: a little flatter and cooler than a photographer's edit.
    img = Image.fromarray(a.astype(np.uint8))
    img = ImageEnhance.Color(img).enhance(0.78)
    img = ImageEnhance.Contrast(img).enhance(0.92)
    a = np.asarray(img).astype(np.float32)
    a *= np.array([0.97, 1.0, 1.03], dtype=np.float32)

    # Vignette and grain.
    vig = 1 - 0.38 * np.clip(r2 / 1.3, 0, 1) ** 1.4
    a *= vig[..., None]
    rng = np.random.default_rng(7)
    a += rng.normal(0, 5.5, size=(H, W, 1)).astype(np.float32)
    img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))

    # Overlay: name and timestamp top left, DEMO badge bottom right.
    d = ImageDraw.Draw(img)
    f = font(40)
    for dx, dy in ((2, 2), (0, 0)):
        fill = (0, 0, 0) if dx else (255, 255, 255)
        d.text((36 + dx, 30 + dy), "Hallway", font=f, fill=fill)
        d.text((36 + dx, 80 + dy), STAMP, font=f, fill=fill)
    small = font(30)
    label = "DEMO"
    tw = d.textlength(label, font=small)
    x1, y1 = 1920 - 40, 1080 - 36
    x0, y0 = x1 - tw - 28, y1 - 46
    d.rounded_rectangle((x0, y0, x1, y1), radius=6, fill=(200, 40, 40))
    d.text((x0 + 14, y0 + 6), label, font=small, fill=(255, 255, 255))

    img.save(HERE / "hallway.jpg", "JPEG", quality=80, optimize=True, progressive=True)


if __name__ == "__main__":
    main(sys.argv[1])
