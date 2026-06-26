#!/usr/bin/env bash
# Remove solid black/white backdrops from tour guide PNGs (no host pip required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATIC="$ROOT/backend/app/static"
SCRIPT="$ROOT/scripts/process-tour-guide-image.py"

cd "$ROOT"

if [[ ! -d "$STATIC" ]]; then
  echo "ERROR: $STATIC not found" >&2
  exit 1
fi

for n in 1 2 3 4; do
  if [[ ! -f "$STATIC/tour-guide-${n}.png" ]]; then
    echo "ERROR: missing $STATIC/tour-guide-${n}.png" >&2
    exit 1
  fi
done

process_with_imagemagick() {
  if ! command -v magick >/dev/null 2>&1 && ! command -v convert >/dev/null 2>&1; then
    return 1
  fi
  local cmd=convert
  if command -v magick >/dev/null 2>&1; then
    cmd="magick"
  fi
  echo "Using ImageMagick ($cmd)..."
  for n in 1 2 3 4; do
    local file="$STATIC/tour-guide-${n}.png"
    $cmd "$file" -fuzz 12% -transparent black -fuzz 8% -transparent white "$file"
    echo "  updated tour-guide-${n}.png"
  done
}

process_with_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi
  echo "Using Docker + Python/Pillow..."
  docker run --rm \
    -v "$STATIC:/out" \
    -v "$SCRIPT:/script.py:ro" \
    python:3.12-slim \
    sh -c "pip install -q pillow && python /script.py"
}

process_with_python() {
  if python3 -c "from PIL import Image" >/dev/null 2>&1; then
    echo "Using local Python/Pillow..."
    python3 "$SCRIPT"
    return 0
  fi
  return 1
}

if process_with_python; then
  :
elif process_with_imagemagick; then
  :
elif process_with_docker; then
  :
else
  echo "ERROR: Could not process images." >&2
  echo "Install one of:" >&2
  echo "  - python3-pillow (yum install python3-pillow)" >&2
  echo "  - ImageMagick (yum install ImageMagick)" >&2
  echo "  - Docker (already used for the app)" >&2
  exit 1
fi

echo "Done. Restart web if needed: docker compose restart web"
