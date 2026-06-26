#!/usr/bin/env bash
# Install train-vmware InSpec plugin inside the running worker container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GEM=$(find stig-profiles/vcf/9.x -name 'train-vmware-*.gem' 2>/dev/null | head -1)

if [ -z "$GEM" ]; then
  echo "ERROR: train-vmware gem not found under stig-profiles/vcf/9.x/"
  echo "Run: bash scripts/setup-stig-profiles.sh ./stig-profiles"
  exit 1
fi

echo "Installing: $GEM"
docker compose exec worker cinc-auditor plugin install "/usr/share/stigs/${GEM#stig-profiles/}"
docker compose exec worker cinc-auditor plugin list
