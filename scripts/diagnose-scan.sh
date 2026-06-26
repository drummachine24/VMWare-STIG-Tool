#!/usr/bin/env bash
# Quick diagnostics for scan failures on the Linux Docker host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== VMware STIG Tool — Scan diagnostics ==="
echo ""

echo "--- Container status ---"
docker compose ps
echo ""

echo "--- Worker tools ---"
docker compose exec worker bash -lc '
  echo "cinc-auditor: $(command -v cinc-auditor || echo MISSING)"
  cinc-auditor version 2>/dev/null | head -1 || true
  echo "saf: $(command -v saf || echo MISSING)"
  saf --version 2>/dev/null | head -1 || true
  echo "pwsh: $(command -v pwsh || echo MISSING)"
  pwsh --version 2>/dev/null | head -1 || true
  echo ""
  echo "--- train-vmware plugin ---"
  cinc-auditor plugin list 2>/dev/null | grep train-vmware || echo "train-vmware NOT installed"
'
echo ""

echo "--- STIG profile paths ---"
docker compose exec worker bash -lc '
  BASE="${STIG_PROFILES_PATH:-/usr/share/stigs}/${VCF_PROFILE_BASE:-vcf/9.x/Y25M09-srg}"
  echo "Profile base: $BASE"
  ls -la "$BASE/inspec/vmware-cloud-foundation-stig-baseline/vsphere/" 2>/dev/null | head -20 || echo "Profile path missing"
  test -f "$BASE/inspec/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml" && echo "inputs-example.yml: OK" || echo "inputs-example.yml: MISSING"
'
echo ""

echo "--- Recent report logs ---"
docker compose exec worker bash -lc 'ls -lt /data/reports/*.log 2>/dev/null | head -5 || echo "No .log files yet"'
echo ""
echo "To read the latest log:"
echo "  docker compose exec worker bash -lc 'ls -t /data/reports/*.log | head -1 | xargs tail -100'"
echo ""
echo "--- Optional PowerCLI host test ---"
echo "Set these in the shell, then run the pwsh block:"
echo "  export VISERVER=your.vcenter.fqdn"
echo "  export VISERVER_USERNAME='Administrator@vsphere.local'"
echo "  export VISERVER_PASSWORD='your-password'"
echo ""
cat <<'EOS'
docker compose exec worker pwsh -Command '
  Import-Module VMware.VimAutomation.Core -ErrorAction Stop
  Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  $sec = ConvertTo-SecureString $env:VISERVER_PASSWORD -AsPlainText -Force
  $cred = New-Object PSCredential($env:VISERVER_USERNAME, $sec)
  Import-Module VMware.VimAutomation.Core
  Connect-VIServer -Server $env:VISERVER -Credential $cred -Force
  Get-VMHost | Select-Object -ExpandProperty Name
  Disconnect-VIServer -Confirm:$false
'
EOS
