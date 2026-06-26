#!/bin/bash
set -euo pipefail

echo "==> Installing PowerShell 7..."
curl -sSL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
apt-get update
apt-get install -y powershell

echo "==> Installing CINC Auditor 7..."
curl -L https://omnitruck.cinc.sh/install.sh | bash -s -- -P cinc-auditor -v 7

echo "==> Installing Node.js + SAF CLI..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs
npm install -g @mitre/saf

echo "==> Installing VCF PowerCLI modules (STIG scan subset only)..."
pwsh -NoProfile -Command "
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  function Install-PowerCLIModule {
    param([string]\$Name, [string]\$MinimumVersion = '')
    Write-Host \"Installing \$Name...\"
    \$params = @{
      Name         = \$Name
      Scope        = 'AllUsers'
      Force        = \$true
      AllowClobber = \$true
      ErrorAction  = 'Stop'
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
  if (-not (Get-Module -ListAvailable VMware.VimAutomation.Core)) {
    throw 'VMware.VimAutomation.Core not found after install'
  }
  Write-Output (\"PowerCLI Core version: \" + (Get-Module VMware.VimAutomation.Core).Version)
"

echo "==> Scan toolchain ready."
cinc-auditor version || true
saf --version || true
pwsh -NoProfile -Command 'Get-Module -ListAvailable VMware.* | Select-Object Name, Version' || true
