#!/usr/bin/env bash
# First-time setup on the Linux Docker host.
# Usage: bash scripts/first-time-setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== VMware STIG Tool — First-time setup ==="
echo "Project root: $ROOT"
echo ""

# --- Prerequisites ---
missing=()
command -v docker >/dev/null 2>&1 || missing+=("docker")
command -v git >/dev/null 2>&1 || missing+=("git")

if ! docker compose version >/dev/null 2>&1 && ! docker-compose version >/dev/null 2>&1; then
  missing+=("docker compose")
fi

if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: Missing required tools: ${missing[*]}"
  echo ""
  echo "Install Docker Engine + Compose plugin on your Linux host, for example:"
  echo "  https://docs.docker.com/engine/install/"
  exit 1
fi

echo "[1/5] Prerequisites OK (docker, git, compose)"

# --- .env file ---
if [ -f .env ]; then
  echo "[2/5] .env already exists — leaving it unchanged"
  echo "      (Delete .env and re-run this script to regenerate keys)"
else
  echo "[2/5] Creating .env with generated secrets..."

  # Generate Fernet key
  if command -v python3 >/dev/null 2>&1; then
    FERNET_KEY=$(python3 - <<'PY'
try:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())
except ImportError:
    import base64, hashlib, os
    print(base64.urlsafe_b64encode(hashlib.sha256(os.urandom(32)).digest()).decode())
PY
)
  else
    echo "      Python3 not found — using Docker to generate Fernet key"
    FERNET_KEY=$(docker run --rm python:3.12-slim sh -c \
      "pip install -q cryptography && python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
  fi

  APP_SECRET=$(openssl rand -base64 32 2>/dev/null | tr -d '/+=' | head -c 43 || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 43)

  cp .env.example .env
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s|CREDENTIAL_ENCRYPTION_KEY=.*|CREDENTIAL_ENCRYPTION_KEY=${FERNET_KEY}|" .env
    sed -i '' "s|APP_SECRET_KEY=.*|APP_SECRET_KEY=${APP_SECRET}|" .env
  else
    sed -i "s|CREDENTIAL_ENCRYPTION_KEY=.*|CREDENTIAL_ENCRYPTION_KEY=${FERNET_KEY}|" .env
    sed -i "s|APP_SECRET_KEY=.*|APP_SECRET_KEY=${APP_SECRET}|" .env
  fi
  echo "      Created .env with unique encryption keys"
fi

# --- Directories ---
echo "[3/5] Ensuring data directories exist..."
mkdir -p data/reports data/ckl-exports data/secrets

if [ -f .env ] && grep -q '^CREDENTIAL_ENCRYPTION_KEY=' .env; then
  FERNET_FROM_ENV=$(grep '^CREDENTIAL_ENCRYPTION_KEY=' .env | cut -d= -f2-)
  if [ -n "$FERNET_FROM_ENV" ] && [ "$FERNET_FROM_ENV" != "change-me-use-fernet-key" ]; then
    printf '%s' "$FERNET_FROM_ENV" > data/secrets/credential_encryption_key
    chmod 600 data/secrets/credential_encryption_key 2>/dev/null || true
    echo "      Wrote data/secrets/credential_encryption_key for worker containers"
  fi
fi stig-profiles

# --- STIG profiles ---
if [ -d "stig-profiles/vcf" ]; then
  echo "[4/5] STIG profiles already present under stig-profiles/vcf/"
else
  echo "[4/5] Downloading VMware STIG profiles (may take a minute)..."
  bash scripts/setup-stig-profiles.sh ./stig-profiles
fi

# --- Detect profile revision folder ---
PROFILE_DIR=$(find stig-profiles/vcf/9.x -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -1 || true)
if [ -n "$PROFILE_DIR" ]; then
  REV=$(basename "$PROFILE_DIR")
  if grep -q "VCF_PROFILE_BASE=" .env; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' "s|VCF_PROFILE_BASE=.*|VCF_PROFILE_BASE=vcf/9.x/${REV}|" .env
    else
      sed -i "s|VCF_PROFILE_BASE=.*|VCF_PROFILE_BASE=vcf/9.x/${REV}|" .env
    fi
    echo "      Set VCF_PROFILE_BASE=vcf/9.x/${REV} in .env"
  fi
else
  echo "      WARNING: No vcf/9.x profile folder found. Run setup-stig-profiles.sh manually."
fi

echo "[5/5] Ready to build and start"
echo ""
echo "Next commands:"
echo "  cd $ROOT"
echo "  docker compose up --build -d"
echo ""
echo "After containers are healthy, install the train-vmware plugin:"
echo "  docker compose exec worker bash -c 'cinc-auditor plugin install /usr/share/stigs/vcf/9.x/*/inspec/*/vsphere/train-vmware-*.gem'"
echo "  docker compose exec worker cinc-auditor plugin list"
echo ""
echo "Then open: http://<linux-host-ip>:8080"
echo ""
echo "Optional — test UI without vCenter first:"
echo "  Set DRY_RUN=true in .env, then: docker compose up -d --force-recreate web worker"
