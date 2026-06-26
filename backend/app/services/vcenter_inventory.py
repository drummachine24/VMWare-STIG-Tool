import json
import logging
import subprocess
import tempfile
from pathlib import Path

from app.config import get_settings
from app.models import VCenterConnection
from app.services.scan_engine import ScanEngine

logger = logging.getLogger(__name__)

INVENTORY_SCRIPT = r"""
param()
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

if (-not $env:VISERVER -or -not $env:VISERVER_USERNAME -or -not $env:VISERVER_PASSWORD) {
  throw 'Missing VISERVER credentials in environment'
}

$sec = ConvertTo-SecureString $env:VISERVER_PASSWORD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:VISERVER_USERNAME, $sec)
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

$vi = Connect-VIServer -Server $env:VISERVER -Credential $cred -Force
try {
  $tree = [ordered]@{
    id = 'vcenter'
    name = $vi.Name
    type = 'vcenter'
    children = @()
  }

  $clusters = Get-Cluster -ErrorAction SilentlyContinue
  if ($clusters) {
    foreach ($cluster in $clusters) {
      $clusterNode = [ordered]@{
        id = ('cluster:' + $cluster.Name)
        name = $cluster.Name
        type = 'cluster'
        children = @()
      }
      $hosts = Get-VMHost -Location $cluster -ErrorAction SilentlyContinue
      foreach ($vmHost in $hosts) {
        $hostNode = [ordered]@{
          id = ('host:' + $vmHost.Name)
          name = $vmHost.Name
          type = 'host'
          children = @()
        }
        $vms = Get-VM -Location $vmHost -ErrorAction SilentlyContinue
        foreach ($vm in $vms) {
          $hostNode.children += [ordered]@{
            id = ('vm:' + $vm.Name)
            name = $vm.Name
            type = 'vm'
          }
        }
        $clusterNode.children += $hostNode
      }
      $tree.children += $clusterNode
    }
  } else {
    $hosts = Get-VMHost -ErrorAction SilentlyContinue
    foreach ($vmHost in $hosts) {
      $hostNode = [ordered]@{
        id = ('host:' + $vmHost.Name)
        name = $vmHost.Name
        type = 'host'
        children = @()
      }
      $vms = Get-VM -Location $vmHost -ErrorAction SilentlyContinue
      foreach ($vm in $vms) {
        $hostNode.children += [ordered]@{
          id = ('vm:' + $vm.Name)
          name = $vm.Name
          type = 'vm'
        }
      }
      $tree.children += $hostNode
    }
  }

  $tree | ConvertTo-Json -Depth 8 -Compress
} finally {
  Disconnect-VIServer -Server $vi -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
"""


def _demo_inventory(vcenter: VCenterConnection) -> dict:
    return {
        "demo": True,
        "id": "vcenter",
        "name": vcenter.hostname,
        "type": "vcenter",
        "children": [
            {
                "id": "host:esxi1.example.local",
                "name": "esxi1.example.local",
                "type": "host",
                "children": [
                    {"id": "vm:demo-vm-1", "name": "demo-vm-1", "type": "vm"},
                ],
            }
        ],
    }


def fetch_inventory(vcenter: VCenterConnection) -> dict:
    settings = get_settings()
    engine = ScanEngine(settings)

    if settings.dry_run:
        logger.info("Returning demo inventory for %s (DRY_RUN=true)", vcenter.hostname)
        return _demo_inventory(vcenter)

    if not _has_pwsh():
        raise RuntimeError(
            "PowerShell (pwsh) is not available in this container. "
            "Inventory must be fetched on the scan worker."
        )

    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8") as tmp:
        tmp.write(INVENTORY_SCRIPT)
        script_path = tmp.name

    env = engine._vcenter_env(vcenter)
    try:
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", script_path],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(detail or f"Inventory script exit code {result.returncode}")

        stdout = result.stdout.strip()
        # PowerCLI may emit warnings before JSON — take last line starting with {
        json_line = stdout
        for line in reversed(stdout.splitlines()):
            if line.strip().startswith("{"):
                json_line = line.strip()
                break

        return json.loads(json_line)
    finally:
        Path(script_path).unlink(missing_ok=True)


def _has_pwsh() -> bool:
    import shutil

    return shutil.which("pwsh") is not None
