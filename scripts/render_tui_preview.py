#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ANSI_RE = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
SCRIPT_NOISE_RE = re.compile(r"^Script (started|done)\b", re.IGNORECASE)
BS_RE = re.compile(r"[^\n]\x08")

TANGO = {
    "bg": "#2E3436",
    "fg": "#EEEEEC",
    "green": "#8AE234",
    "yellow": "#FCE94F",
    "red": "#EF2929",
    "dim": "#888A85",
}


def _find_font(path: str | None) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    candidates.extend(
        [
            Path("/Library/Fonts/Anonymous Pro.ttf"),
            Path("/Library/Fonts/AnonymousPro-Regular.ttf"),
            Path("/System/Library/Fonts/Supplemental/Anonymous Pro.ttf"),
            Path.home() / "Library/Fonts/Anonymous Pro.ttf",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size=18)
    return ImageFont.load_default()


def _sanitize(raw: str) -> list[str]:
    text = ANSI_RE.sub("", raw)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    while BS_RE.search(text):
        text = BS_RE.sub("", text)
    lines = [line.rstrip() for line in text.splitlines()]
    lines = [line for line in lines if line and not SCRIPT_NOISE_RE.match(line)]
    return lines


def _line_color(line: str) -> str:
    if line.startswith("✓"):
        return TANGO["green"]
    if line.startswith("⚠"):
        return TANGO["yellow"]
    if line.startswith("✗"):
        return TANGO["red"]
    if line.startswith("Tip:"):
        return TANGO["dim"]
    return TANGO["fg"]


def _render_frame(
    *,
    lines: list[str],
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    columns: int,
    rows: int,
) -> Image.Image:
    char_box = font.getbbox("M")
    char_width = max(1, char_box[2] - char_box[0])
    line_height = max(1, (char_box[3] - char_box[1]) + 4)
    width = columns * char_width + 20
    height = rows * line_height + 20
    image = Image.new("RGB", (width, height), color=TANGO["bg"])
    draw = ImageDraw.Draw(image)
    for idx, line in enumerate(lines[-rows:]):
        clipped = line[:columns]
        draw.text((10, 10 + idx * line_height), clipped, fill=_line_color(clipped), font=font)
    return image


def main() -> None:
    parser = argparse.ArgumentParser(description="Render TTY transcript preview (PNG+GIF).")
    parser.add_argument("--input", required=True, help="Input transcript text file.")
    parser.add_argument("--png", required=True, help="Output PNG path.")
    parser.add_argument("--gif", required=True, help="Output GIF path.")
    parser.add_argument("--duration", type=float, default=30.0, help="GIF duration in seconds.")
    parser.add_argument("--fps", type=int, default=8, help="GIF frames per second.")
    parser.add_argument("--columns", type=int, default=120, help="Rendered terminal width.")
    parser.add_argument("--rows", type=int, default=34, help="Rendered terminal height.")
    parser.add_argument("--font-path", default=None, help="Optional Anonymous Pro font path.")
    args = parser.parse_args()

    input_path = Path(args.input)
    png_path = Path(args.png)
    gif_path = Path(args.gif)
    png_path.parent.mkdir(parents=True, exist_ok=True)
    gif_path.parent.mkdir(parents=True, exist_ok=True)

    raw = input_path.read_text(encoding="utf-8", errors="ignore")
    lines = _sanitize(raw)
    if not lines:
        lines = ["(no output captured)"]

    font = _find_font(args.font_path)
    total_frames = max(1, int(round(args.duration * args.fps)))
    frames: list[Image.Image] = []
    for i in range(total_frames):
        visible = max(1, int((i + 1) / total_frames * len(lines)))
        frame = _render_frame(
            lines=lines[:visible],
            font=font,
            columns=args.columns,
            rows=args.rows,
        )
        frames.append(frame)

    frames[-1].save(png_path, format="PNG")
    frame_duration_ms = max(20, int(1000 / max(1, args.fps)))
    frames[0].save(
        gif_path,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        duration=frame_duration_ms,
        loop=0,
        optimize=False,
        disposal=2,
    )


if __name__ == "__main__":
    main()
