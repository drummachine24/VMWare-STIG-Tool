#!/usr/bin/env bash
# Rebuild Docker images on the RHEL Docker host and roll out updated containers.
#
# Safe to bake into images:
#   - backend/app (Python app, templates, static assets)
#   - backend/requirements.txt
#   - worker/install-scan-tools.sh
#
# Still mounted at runtime (not baked):
#   - data/reports, data/ckl-exports, data/secrets
#   - stig-profiles, certs
#
# Usage:
#   bash scripts/rebuild-on-server.sh          # dev: rebuild images (bind mounts still override app code)
#   bash scripts/rebuild-on-server.sh --prod   # prod: bake app code into image, no bind mounts
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROD=false
NO_PULL=false
for arg in "$@"; do
  case "$arg" in
    --prod) PROD=true ;;
    --no-pull) NO_PULL=true ;;
    -h|--help)
      echo "Usage: $0 [--prod] [--no-pull]"
      echo "  --prod     Use docker-compose.prod.yml (app code from image, not bind mounts)"
      echo "  --no-pull  Skip git pull"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Run this script on the RHEL Docker host." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin not found." >&2
  exit 1
fi

COMPOSE_FILES=(-f docker-compose.yml)
if [ "$PROD" = true ]; then
  COMPOSE_FILES+=(-f docker-compose.prod.yml)
  echo "=== Production mode: app code will run from built images ==="
else
  echo "=== Dev mode: ./backend/app bind mount still overrides image code at runtime ==="
  echo "    Use --prod to bake and run application code from the image."
fi

if [ "$NO_PULL" = false ]; then
  if [ -d .git ]; then
    echo ""
    echo "=== Pulling latest code ==="
    git pull
  else
    echo ""
    echo "=== Skipping git pull (not a git checkout) ==="
  fi
fi

echo ""
echo "=== Building images (web, worker, scheduler) ==="
docker compose "${COMPOSE_FILES[@]}" build web worker scheduler

echo ""
echo "=== Recreating containers ==="
docker compose "${COMPOSE_FILES[@]}" up -d --force-recreate web worker scheduler

echo ""
echo "=== Status ==="
docker compose "${COMPOSE_FILES[@]}" ps web worker scheduler

echo ""
echo "Done."
if [ "$PROD" = true ]; then
  echo "Verify scans page has delete/pagination: open the web UI and check /scans"
else
  echo "Tip: after git pull, dev bind mounts may already have new code."
  echo "     Run with --prod to deploy strictly from rebuilt images."
fi
