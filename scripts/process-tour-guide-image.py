#!/usr/bin/env python3
"""Remove solid backdrops from tour guide PNGs in backend/app/static/."""
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path("/out") if Path("/out/tour-guide-1.png").is_file() else ROOT / "backend" / "app" / "static"
FILES = [STATIC / f"tour-guide-{index}.png" for index in range(1, 5)]


def strip_backdrop(path: Path) -> None:
    img = Image.open(path).convert("RGBA")
    pixels = img.load()
    width, height = img.size
    for y in range(height):
        for x in range(width):
            red, green, blue, alpha = pixels[x, y]
            if red < 28 and green < 28 and blue < 28:
                pixels[x, y] = (red, green, blue, 0)
            elif red > 232 and green > 232 and blue > 232:
                pixels[x, y] = (red, green, blue, 0)
    img.save(path)
    print(f"Updated {path.name} ({width}x{height})")


def main() -> None:
    for path in FILES:
        if not path.is_file():
            raise SystemExit(f"Missing {path}")
        strip_backdrop(path)


if __name__ == "__main__":
    main()
