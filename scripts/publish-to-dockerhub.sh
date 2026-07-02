#!/usr/bin/env bash
# Build and push VMware STIG Tool images to Docker Hub.
#
# Prerequisites (on the RHEL Docker host):
#   1. docker login
#   2. export DOCKER_IMAGE_PREFIX=yourdockerhubuser/
#   3. optional: export IMAGE_TAG=1.0.0
#
# Usage:
#   export DOCKER_IMAGE_PREFIX=yourdockerhubuser/
#   bash scripts/publish-to-dockerhub.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -z "${DOCKER_IMAGE_PREFIX:-}" ]; then
  echo "ERROR: Set DOCKER_IMAGE_PREFIX to your Docker Hub username with a trailing slash." >&2
  echo "Example: export DOCKER_IMAGE_PREFIX=drummachine24/" >&2
  exit 1
fi

IMAGE_TAG="${IMAGE_TAG:-latest}"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.prod.yml)

echo "=== Docker Hub publish ==="
echo "Prefix: ${DOCKER_IMAGE_PREFIX}"
echo "Tag:    ${IMAGE_TAG}"
echo ""

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker is not running or not accessible." >&2
  exit 1
fi

echo "=== Log in to Docker Hub (skip if already logged in) ==="
docker login

echo ""
echo "=== Building images ==="
"${COMPOSE[@]}" build web worker scheduler

echo ""
echo "=== Pushing images ==="
"${COMPOSE[@]}" push web worker scheduler

echo ""
echo "Published:"
echo "  ${DOCKER_IMAGE_PREFIX}vmstigtool-web:${IMAGE_TAG}"
echo "  ${DOCKER_IMAGE_PREFIX}vmstigtool-worker:${IMAGE_TAG}"
echo "  ${DOCKER_IMAGE_PREFIX}vmstigtool-scheduler:${IMAGE_TAG}"
echo ""
echo "On another host, pull and run with:"
echo "  export DOCKER_IMAGE_PREFIX=${DOCKER_IMAGE_PREFIX}"
echo "  export IMAGE_TAG=${IMAGE_TAG}"
echo "  docker compose -f docker-compose.yml -f docker-compose.prod.yml pull web worker scheduler"
echo "  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
