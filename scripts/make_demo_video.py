"""Builds the demo video from the frames of one real session (dashboard/scripts/demo-frames.mjs).

    uv run --with imageio-ffmpeg python scripts/make_demo_video.py [frames_dir] [out.mp4]

Every scene is a real screenshot with a caption. The comparison run is sped up, and the title card
and its caption say so, with the real run time. imageio-ffmpeg brings its own ffmpeg binary, so
nothing is installed system-wide; it isn't a project dependency.
"""

import json
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

SIZE = (1280, 800)
FPS = 12
BACKGROUND = (11, 15, 23)
INK = (235, 238, 243)
MUTED = (160, 170, 185)
ACCENT = (96, 150, 255)
# The article sits in a narrow column: these scenes zoom into it (same 1.6 aspect as the video).
ZOOM = {"page": (300, 0, 1140, 525), "reveal": (300, 0, 1140, 525)}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    names = ("segoeuib.ttf", "DejaVuSans-Bold.ttf") if bold else ("segoeui.ttf", "DejaVuSans.ttf")
    for name in (*names, "Arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def card(lines: list[tuple[str, int, bool, tuple[int, int, int]]]) -> Image.Image:
    """A centred text card: (text, size, bold, colour) per line."""
    image = Image.new("RGB", SIZE, BACKGROUND)
    draw = ImageDraw.Draw(image)
    fonts = [font(size, bold) for _, size, bold, _ in lines]
    heights = [
        draw.textbbox((0, 0), text, font=f)[3] for (text, *_), f in zip(lines, fonts, strict=True)
    ]
    y = (SIZE[1] - sum(heights) - 28 * (len(lines) - 1)) // 2
    for (text, _, _, colour), f, height in zip(lines, fonts, heights, strict=True):
        width = draw.textlength(text, font=f)
        draw.text(((SIZE[0] - width) / 2, y), text, font=f, fill=colour)
        y += height + 28
    return image


def captioned(path: Path, scene: str, caption: str) -> Image.Image:
    image = Image.open(path).convert("RGB")
    if scene in ZOOM:
        image = image.crop(ZOOM[scene])
    image = image.resize(SIZE, Image.Resampling.LANCZOS)
    overlay = Image.new("RGBA", SIZE, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    f = font(26)
    lines = textwrap.wrap(caption, width=80)
    line_height = 36
    band = 28 + line_height * len(lines)
    draw.rectangle((0, SIZE[1] - band, SIZE[0], SIZE[1]), fill=(8, 11, 17, 225))
    y = SIZE[1] - band + 14
    for line in lines:
        width = draw.textlength(line, font=f)
        draw.text(((SIZE[0] - width) / 2, y), line, font=f, fill=INK)
        y += line_height
    return Image.alpha_composite(image.convert("RGBA"), overlay).convert("RGB")


def frames(frames_dir: Path) -> Iterator[tuple[Image.Image, float]]:
    meta = json.loads((frames_dir / "frames.json").read_text(encoding="utf-8"))
    running = [shot for shot in meta["shots"] if shot["scene"] == "running"]
    shown = len(running) * running[0]["seconds"] if running else 1.0
    speedup = meta["seconds"] / shown
    yield (
        card(
            [
                ("PromptShield", 72, True, INK),
                ("A real-time firewall for AI agents", 34, False, ACCENT),
                ("A real session on a laptop CPU. The comparison run is shown", 24, False, MUTED),
                (
                    f"about {speedup:.0f}x faster ({meta['seconds']} s in real time).",
                    24,
                    False,
                    MUTED,
                ),
            ]
        ),
        4.0,
    )
    for shot in meta["shots"]:
        caption = shot["caption"]
        if shot["scene"] == "running":
            caption = f"Live run on a laptop CPU, shown about {speedup:.0f}x faster."
        yield captioned(frames_dir / shot["file"], shot["scene"], caption), shot["seconds"]
    yield (
        card(
            [
                ("Open source · runs 100% locally · no paid APIs", 32, True, INK),
                ("github.com/insjunaid/PromptShield", 30, False, ACCENT),
                ("Built by Junaid", 24, False, MUTED),
            ]
        ),
        4.0,
    )


def build(frames_dir: Path, out: Path) -> None:
    import imageio_ffmpeg  # type: ignore[import-not-found]

    writer = imageio_ffmpeg.write_frames(
        str(out),
        SIZE,
        fps=FPS,
        codec="libx264",
        quality=7,
        pix_fmt_out="yuv420p",
        macro_block_size=16,
        output_params=["-movflags", "+faststart"],
    )
    writer.send(None)
    total = 0.0
    for image, seconds in frames(frames_dir):
        data = np.asarray(image, dtype=np.uint8)
        for _ in range(max(1, round(seconds * FPS))):
            writer.send(data)
        total += seconds
    writer.close()
    print(f"{out}: {total:.0f} s, {out.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/demo_frames")
    target = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/demo.mp4")
    build(source, target)
