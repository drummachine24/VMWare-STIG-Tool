#!/usr/bin/env bash
# Install/repair PowerCLI inside the running worker container (no full image rebuild).
# Installs only the modules required for VCF STIG scanning — NOT the full VMware.PowerCLI bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Installing PowerCLI modules in worker container ==="
echo "    (Core, Vds, Storage, SsoAdmin — skipping optional vROps etc.)"
echo ""

docker compose exec worker pwsh -NoProfile -Command "
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

  function Install-PowerCLIModule {
    param([string]\$Name, [string]\$MinimumVersion = '')
    Write-Host \"Installing \$Name...\"
    \$params = @{
      Name            = \$Name
      Scope           = 'AllUsers'
      Force           = \$true
      AllowClobber    = \$true
      ErrorAction     = 'Stop'
    }
    if (\$MinimumVersion) { \$params['MinimumVersion'] = \$MinimumVersion }
    Install-Module @params
  }

  Install-PowerCLIModule 'VMware.VimAutomation.Core'
  Install-PowerCLIModule 'VMware.VimAutomation.Vds'
  Install-PowerCLIModule 'VMware.VimAutomation.Storage'
  Install-PowerCLIModule 'VMware.Vsphere.SsoAdmin' '1.4.0'

  Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP \$false -Confirm:\$false -ErrorAction SilentlyContinue | Out-Null
  Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCeip \$false -Confirm:\$false -ErrorAction SilentlyContinue | Out-Null
  Set-PowerCLIConfiguration -Scope AllUsers -InvalidCertificateAction Ignore -Confirm:\$false -ErrorAction SilentlyContinue | Out-Null

  Import-Module VMware.VimAutomation.Core -ErrorAction Stop
  Write-Host ''
  Write-Host \"PowerCLI Core version: \$((Get-Module VMware.VimAutomation.Core).Version)\"
  Write-Host ''
  Get-Module -ListAvailable VMware.* | Select-Object Name, Version | Format-Table -AutoSize
"

echo ""
echo "Done. Verify with:"
echo "  docker compose exec worker pwsh -Command \"Import-Module VMware.VimAutomation.Core; (Get-Module VMware.VimAutomation.Core).Version\""
