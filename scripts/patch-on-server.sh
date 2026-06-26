#!/usr/bin/env bash
# Apply critical scan_engine fixes on the Linux server (no full redeploy from Windows).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FILE="backend/app/services/scan_engine.py"

if [ ! -f "$FILE" ]; then
  echo "ERROR: $FILE not found"
  exit 1
fi

echo "=== Patching $FILE ==="

cp "$FILE" "${FILE}.bak.$(date +%Y%m%d%H%M%S)"

# Remove invalid PowerCLI parameter for VCF PowerCLI 9+
if grep -q DisplayLicenseWarnings "$FILE"; then
  sed -i '/DisplayLicenseWarnings/d' "$FILE"
  echo "Removed DisplayLicenseWarnings"
else
  echo "DisplayLicenseWarnings already absent"
fi

# Prevent InSpec lockfile writes to read-only STIG profile mount
if grep -q '\-\-no-create-lockfile' "$FILE"; then
  echo "--no-create-lockfile already present"
else
  sed -i 's/"--enhanced-outcomes",/"--enhanced-outcomes",\n            "--no-create-lockfile",/g' "$FILE"
  echo "Added --no-create-lockfile"
fi

echo ""
echo "=== Restarting worker ==="
docker compose restart worker

echo ""
echo "=== Verify ==="
docker compose exec worker grep -c DisplayLicenseWarnings /app/app/services/scan_engine.py || true
docker compose exec worker grep -c no-create-lockfile /app/app/services/scan_engine.py || true
echo "Done. Re-run a vCenter Product only scan."
