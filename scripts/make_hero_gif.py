"""Builds the README's hero GIF from frames of one real lab run (dashboard/scripts/hero-frames.mjs).

    uv run python scripts/make_hero_gif.py [frames_dir] [out.gif]

Every frame is a real screenshot. The run is sped up, so each frame carries a caption saying so,
with the real run time; the last frame is held so the two verdicts can be read.
"""

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 960
FRAME_MS = 140
HOLD_MS = 4000
FIRST_MS = 1200
MAX_FRAMES = 60  # keeps the GIF small: running frames are thinned evenly


def caption_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in ("segoeui.ttf", "DejaVuSans.ttf", "Arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def thin(names: list[str], limit: int) -> list[str]:
    """Keep the first and last frame and spread the rest evenly."""
    if len(names) <= limit:
        return names
    step = (len(names) - 1) / (limit - 1)
    return [names[round(i * step)] for i in range(limit)]


def build(frames_dir: Path, out: Path) -> None:
    meta = json.loads((frames_dir / "frames.json").read_text(encoding="utf-8"))
    names = thin([item["name"] for item in meta["frames"]], MAX_FRAMES)
    speedup = meta["seconds"] * 1000 / max(len(names) * FRAME_MS, 1)
    text = (
        f"Real run of {meta['scenario']} on a laptop CPU, {meta['seconds']} s, "
        f"shown about {speedup:.0f}x faster"
    )
    font = caption_font(16)
    images: list[Image.Image] = []
    for name in names:
        image = Image.open(frames_dir / name).convert("RGB")
        image = image.resize(
            (WIDTH, round(image.height * WIDTH / image.width)), Image.Resampling.LANCZOS
        )
        draw = ImageDraw.Draw(image)
        box = draw.textbbox((0, 0), text, font=font)
        pad = 8
        width, height = box[2] - box[0], box[3] - box[1]
        x, y = WIDTH - width - 2 * pad - 12, image.height - height - 2 * pad - 12
        draw.rounded_rectangle(
            (x, y, x + width + 2 * pad, y + height + 2 * pad), radius=6, fill=(17, 20, 24)
        )
        draw.text((x + pad, y + pad - box[1]), text, font=font, fill=(230, 233, 238))
        images.append(image.quantize(colors=128, method=Image.Quantize.MEDIANCUT))
    durations = [FIRST_MS] + [FRAME_MS] * (len(images) - 2) + [HOLD_MS]
    images[0].save(
        out,
        save_all=True,
        append_images=images[1:],
        duration=durations[: len(images)],
        loop=0,
        optimize=True,
    )
    print(f"{out}: {len(images)} frames, {out.stat().st_size / 1e6:.1f} MB, {text}")


if __name__ == "__main__":
    frames = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/hero_frames")
    target = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/screenshots/hero.gif")
    build(frames, target)
