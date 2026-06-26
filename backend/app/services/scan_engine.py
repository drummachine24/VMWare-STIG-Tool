import hashlib
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings, get_settings
from app.models import ScanJob, ScanStatus, ScanTargetType, VCenterConnection
from app.services.crypto import decrypt_secret
from app.services.result_parser import parse_scan_artifact

logger = logging.getLogger(__name__)

HOST_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-.]{0,253}[a-zA-Z0-9])?$")
POWERCLI_NOISE_MARKERS = (
    "WARNING:",
    "VMware",
    "CEIP",
    "Set-PowerCLI",
    "Please consider",
    "Customer Experience",
)


@dataclass
class ScanTargetConfig:
    scan_esxi: bool = True
    scan_vms: bool = True
    scan_vcenter_product: bool = True
    scan_vcenter_appliance: bool = False
    esxi_scope: str = "all_hosts"
    esxi_cluster: str | None = None
    esxi_host: str | None = None
    vm_scope: str = "all"


@dataclass
class ScanRunResult:
    target_type: str
    target_name: str
    status: str
    json_path: str | None = None
    ckl_path: str | None = None
    passed: int | None = None
    failed: int | None = None
    skipped: int | None = None
    count_nf: int | None = None
    count_nr: int | None = None
    count_na: int | None = None
    count_open: int | None = None
    summary: str | None = None


@dataclass
class ScanExecutionResult:
    results: list[ScanRunResult] = field(default_factory=list)
    error: str | None = None


class ScanEngine:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.reports_dir = Path(self.settings.reports_path)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def profile_root(self) -> Path:
        return Path(self.settings.stig_profiles_path) / self.settings.vcf_profile_base

    def baseline_profile_path(self) -> Path:
        return self.profile_root() / self.settings.vcf_baseline_profile

    def vcsa_profile_path(self) -> Path:
        return self.profile_root() / self.settings.vcf_vcsa_profile

    def metadata_path(self) -> Path:
        return self.profile_root() / self.settings.vcf_metadata

    def vcsa_metadata_path(self) -> Path:
        return self.vcsa_profile_path() / "saf_cli_hdf2ckl_metadata.json"

    def profiles_available(self) -> bool:
        return self.baseline_profile_path().exists()

    @staticmethod
    def _is_valid_host_label(value: str) -> bool:
        line = value.strip()
        if not line or len(line) > 253 or " " in line:
            return False
        if any(marker in line for marker in POWERCLI_NOISE_MARKERS):
            return False
        return bool(HOST_LABEL_RE.match(line))

    def _safe_report_slug(self, target_name: str, max_len: int = 64) -> str:
        slug = re.sub(r"[^\w\-.]+", "_", target_name.strip(), flags=re.ASCII)
        slug = slug.strip("._") or "target"
        if len(slug) > max_len:
            digest = hashlib.sha256(target_name.encode()).hexdigest()[:10]
            slug = f"{slug[: max_len - 11]}_{digest}"
        return slug

    def _report_paths(
        self, job_id: int, target_type: str, target_name: str
    ) -> tuple[Path, Path, Path, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = self._safe_report_slug(target_name)
        base = f"job{job_id}-{target_type}-{slug}-{timestamp}"
        json_path = self.reports_dir / f"{base}.json"
        ckl_path = self.reports_dir / f"{base}.ckl"
        meta_path = self.reports_dir / f"{base}.metadata.json"
        return json_path, ckl_path, meta_path, slug

    def _vcenter_env(self, vcenter: VCenterConnection) -> dict[str, str]:
        env = os.environ.copy()
        env["VISERVER"] = vcenter.hostname
        env["VISERVER_USERNAME"] = vcenter.api_username
        env["VISERVER_PASSWORD"] = decrypt_secret(vcenter.api_password_encrypted)
        env["NO_COLOR"] = "true"
        return env

    def _run_command(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        logger.info("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd,
            timeout=self.settings.scan_timeout_seconds,
            check=False,
        )

    def _default_inputs(self) -> dict:
        example = self.baseline_profile_path() / "inputs-example.yml"
        if example.exists():
            try:
                import yaml

                loaded = yaml.safe_load(example.read_text(encoding="utf-8")) or {}
                if isinstance(loaded, dict):
                    return loaded
            except Exception as exc:
                logger.warning("Could not load %s: %s", example, exc)
        return {
            "esx_vmhostName": "",
            "esx_cluster": "",
            "esx_allHosts": False,
            "esx_ntpServers": ["time-a-g.nist.gov", "time-b-g.nist.gov"],
            "esx_vmotionVlanId": "100",
            "esx_lockdownExceptionUsers": [],
            "esx_snmpEnabled": "false",
            "vcenter_ntpServers": ["time-a-g.nist.gov", "time-b-g.nist.gov"],
            "vcenter_ipfixCollectorAddresses": [],
            "vcenter_allowedTrunkingPortgroups": [],
            "vcenter_bashShellAdminUsers": ["Administrator"],
            "vcenter_bashShellAdminGroups": [],
            "vcenter_portMirrorSessions": [],
            "vm_Name": "",
            "vm_cluster": "",
            "vm_allvms": True,
        }

    def _write_inputs_file(
        self, job: ScanJob, vcenter: VCenterConnection, overrides: dict | None = None
    ) -> Path:
        inputs = self._default_inputs()
        if job.inputs_yaml:
            try:
                import yaml

                custom = yaml.safe_load(job.inputs_yaml) or {}
                if isinstance(custom, dict):
                    inputs.update(custom)
            except Exception:
                pass
        if overrides:
            inputs.update(overrides)

        try:
            import yaml

            content = yaml.dump(inputs, default_flow_style=False, sort_keys=False)
        except ImportError:
            content = json.dumps(inputs, indent=2)

        path = self.reports_dir / f"inputs-job-{job.id}.yml"
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def _format_command_output(result: subprocess.CompletedProcess[str], limit: int = 2000) -> str:
        chunks = []
        if result.stdout and result.stdout.strip():
            chunks.append(f"stdout:\n{result.stdout.strip()}")
        if result.stderr and result.stderr.strip():
            chunks.append(f"stderr:\n{result.stderr.strip()}")
        text = "\n\n".join(chunks).strip()
        if not text:
            return f"Exit code {result.returncode} with no output"
        if len(text) > limit:
            return text[-limit:]
        return text

    def _parse_inspec_summary(self, stdout: str) -> tuple[int | None, int | None, int | None, str]:
        passed = failed = skipped = None
        summary_line = ""
        for line in stdout.splitlines():
            if "Profile Summary:" in line or "Test Summary:" in line:
                summary_line = line.strip()
            if "successful controls" in line.lower() or "Profile Summary:" in line:
                summary_line = line.strip()
        if summary_line:
            import re

            nums = [int(x) for x in re.findall(r"\d+", summary_line)]
            if len(nums) >= 3:
                passed, failed, skipped = nums[0], nums[1], nums[2]
        return passed, failed, skipped, summary_line

    def _stig_counts_from_artifacts(
        self,
        json_path: Path,
        ckl_path: Path | None,
        stdout: str,
    ) -> tuple[int | None, int | None, int | None, int | None, str]:
        ckl = ckl_path if ckl_path and ckl_path.exists() else None
        combined_output = stdout or ""
        log_path = json_path.with_suffix(".log")
        if log_path.exists():
            try:
                combined_output += "\n" + log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        parsed = parse_scan_artifact(json_path, ckl, combined_output)
        c = parsed.counts
        summary = parsed.summary or (
            f"{c.nf} NF / {c.open} Open / {c.nr} NR / {c.na} NA"
            if any([c.nf, c.open, c.nr, c.na])
            else ""
        )
        return c.nf, c.nr, c.na, c.open, summary

    def _write_ckl_metadata(
        self,
        template_path: Path,
        host_fields: dict,
        output_path: Path,
    ) -> Path:
        if template_path.exists():
            try:
                meta = json.loads(template_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        else:
            meta = {}
        meta.update(host_fields)
        output_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return output_path

    def _convert_to_ckl(
        self,
        json_path: Path,
        ckl_path: Path,
        host_metadata: dict | None = None,
        metadata_template: Path | None = None,
        meta_path: Path | None = None,
    ) -> bool:
        if self.settings.dry_run or not shutil.which("saf"):
            if self.settings.dry_run:
                ckl_path.write_text("<CHECKLIST dry-run='true'/>", encoding="utf-8")
            return False

        meta_file: Path | None = None
        if host_metadata or metadata_template:
            meta_file = meta_path or json_path.with_suffix(".metadata.json")
            self._write_ckl_metadata(
                metadata_template or Path(),
                host_metadata or {},
                meta_file,
            )
        elif meta_path and meta_path.exists():
            meta_file = meta_path
        elif self.metadata_path().exists():
            meta_file = self.metadata_path()

        cmd = ["saf", "convert", "hdf2ckl", "-i", str(json_path), "-o", str(ckl_path)]
        if meta_file:
            cmd.extend(["-m", str(meta_file)])

        result = self._run_command(cmd)
        if result.returncode != 0:
            logger.warning("CKL conversion failed: %s", result.stderr)
            return False
        return True

    def _run_inspec_powercli(
        self,
        profile_subdir: str,
        target_name: str,
        target_type: str,
        job: ScanJob,
        vcenter: VCenterConnection,
        inputs_overrides: dict | None = None,
    ) -> ScanRunResult:
        json_path, ckl_path, meta_path, _slug = self._report_paths(
            job.id, target_type, target_name
        )

        if self.settings.dry_run or not shutil.which("cinc-auditor"):
            sample = {
                "platform": {"name": "vmware", "release": "9.x"},
                "profiles": [{"name": target_type, "controls": []}],
                "dry_run": True,
            }
            json_path.write_text(json.dumps(sample, indent=2), encoding="utf-8")
            self._convert_to_ckl(json_path, ckl_path)
            return ScanRunResult(
                target_type=target_type,
                target_name=target_name,
                status=ScanStatus.COMPLETED.value,
                json_path=str(json_path),
                ckl_path=str(ckl_path) if ckl_path.exists() else None,
                passed=0,
                failed=0,
                skipped=0,
                summary="Dry-run scan (no cinc-auditor or DRY_RUN=true)",
            )

        profile_path = self.baseline_profile_path() / profile_subdir
        if not profile_path.exists():
            return ScanRunResult(
                target_type=target_type,
                target_name=target_name,
                status=ScanStatus.FAILED.value,
                summary=f"Profile not found: {profile_path}",
            )

        inputs_file = self._write_inputs_file(job, vcenter, inputs_overrides)
        env = self._vcenter_env(vcenter)
        cmd = [
            "cinc-auditor",
            "exec",
            str(profile_path),
            "-t",
            "vmware://",
            "--show-progress",
            "--enhanced-outcomes",
            "--no-create-lockfile",
            "--input-file",
            str(inputs_file),
            "--reporter",
            f"json:{json_path}",
        ]
        result = self._run_command(cmd, env=env, cwd=self.reports_dir)
        log_path = json_path.with_suffix(".log")
        log_path.write_text(self._format_command_output(result, limit=50000), encoding="utf-8")

        passed, failed, skipped, summary = self._parse_inspec_summary(result.stdout + result.stderr)

        status = ScanStatus.COMPLETED.value if result.returncode in (0, 100, 101) else ScanStatus.FAILED.value
        host_metadata = {
            "hostname": target_name,
            "hostip": vcenter.hostname,
            "hostfqdn": target_name,
        }
        ckl_ok = self._convert_to_ckl(
            json_path,
            ckl_path,
            host_metadata=host_metadata,
            metadata_template=self.metadata_path(),
            meta_path=meta_path,
        )

        output_text = result.stdout + result.stderr
        count_nf, count_nr, count_na, count_open, stig_summary = self._stig_counts_from_artifacts(
            json_path, ckl_path if ckl_ok else None, output_text
        )
        if not stig_summary:
            _, _, _, _, stig_summary = self._stig_counts_from_artifacts(json_path, None, output_text)

        if status == ScanStatus.FAILED.value:
            summary = summary or self._format_command_output(result)
            summary = f"{stig_summary}\n\n{summary}\n\nLog: {log_path}" if stig_summary else f"{summary}\n\nLog: {log_path}"
        else:
            summary = stig_summary or summary

        return ScanRunResult(
            target_type=target_type,
            target_name=target_name,
            status=status,
            json_path=str(json_path) if json_path.exists() else None,
            ckl_path=str(ckl_path) if ckl_ok else None,
            passed=passed,
            failed=failed,
            skipped=skipped,
            count_nf=count_nf,
            count_nr=count_nr,
            count_na=count_na,
            count_open=count_open,
            summary=summary,
        )

    def _run_inspec_ssh_appliance(
        self, job: ScanJob, vcenter: VCenterConnection
    ) -> ScanRunResult:
        target_name = vcenter.hostname
        json_path, ckl_path, meta_path, _slug = self._report_paths(
            job.id, ScanTargetType.VCENTER_APPLIANCE.value, target_name
        )

        if not vcenter.ssh_password_encrypted:
            return ScanRunResult(
                target_type=ScanTargetType.VCENTER_APPLIANCE.value,
                target_name=target_name,
                status=ScanStatus.FAILED.value,
                summary="SSH credentials not configured for appliance scan",
            )

        if self.settings.dry_run or not shutil.which("cinc-auditor"):
            json_path.write_text('{"dry_run": true}', encoding="utf-8")
            self._convert_to_ckl(json_path, ckl_path)
            return ScanRunResult(
                target_type=ScanTargetType.VCENTER_APPLIANCE.value,
                target_name=target_name,
                status=ScanStatus.COMPLETED.value,
                json_path=str(json_path),
                ckl_path=str(ckl_path) if ckl_path.exists() else None,
                summary="Dry-run appliance scan",
            )

        profile_path = self.vcsa_profile_path()
        if not profile_path.exists():
            return ScanRunResult(
                target_type=ScanTargetType.VCENTER_APPLIANCE.value,
                target_name=target_name,
                status=ScanStatus.FAILED.value,
                summary=f"VCSA profile not found: {profile_path}",
            )

        ssh_user = vcenter.ssh_username or "root"
        ssh_password = decrypt_secret(vcenter.ssh_password_encrypted)
        cmd = [
            "cinc-auditor",
            "exec",
            str(profile_path),
            "-t",
            f"ssh://{ssh_user}@{vcenter.hostname}",
            "--password",
            ssh_password,
            "--show-progress",
            "--enhanced-outcomes",
            "--no-create-lockfile",
            "--reporter",
            f"json:{json_path}",
        ]
        result = self._run_command(cmd, cwd=self.reports_dir)
        passed, failed, skipped, summary = self._parse_inspec_summary(result.stdout + result.stderr)
        status = ScanStatus.COMPLETED.value if result.returncode in (0, 100, 101) else ScanStatus.FAILED.value
        host_metadata = {
            "hostname": target_name,
            "hostip": target_name,
            "hostfqdn": target_name,
        }
        ckl_ok = self._convert_to_ckl(
            json_path,
            ckl_path,
            host_metadata=host_metadata,
            metadata_template=self.vcsa_metadata_path(),
            meta_path=meta_path,
        )

        output_text = result.stdout + result.stderr
        count_nf, count_nr, count_na, count_open, stig_summary = self._stig_counts_from_artifacts(
            json_path, ckl_path if ckl_ok else None, output_text
        )
        summary = stig_summary or summary or (result.stderr[-500:] if result.stderr else None)

        return ScanRunResult(
            target_type=ScanTargetType.VCENTER_APPLIANCE.value,
            target_name=target_name,
            status=status,
            json_path=str(json_path),
            ckl_path=str(ckl_path) if ckl_ok else None,
            passed=passed,
            failed=failed,
            skipped=skipped,
            count_nf=count_nf,
            count_nr=count_nr,
            count_na=count_na,
            count_open=count_open,
            summary=summary,
        )

    def _list_esxi_hosts(
        self, vcenter: VCenterConnection, job: ScanJob
    ) -> tuple[list[str], str | None]:
        if self.settings.dry_run or not shutil.which("pwsh"):
            return ["esxi1.example.local", "esxi2.example.local"], None

        script = r"""
param($Cluster, $HostName, $Scope)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

if (-not $env:VISERVER -or -not $env:VISERVER_USERNAME -or -not $env:VISERVER_PASSWORD) {
  throw 'Missing VISERVER, VISERVER_USERNAME, or VISERVER_PASSWORD environment variables'
}

$sec = ConvertTo-SecureString $env:VISERVER_PASSWORD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:VISERVER_USERNAME, $sec)
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Connect-VIServer -Server $env:VISERVER -Credential $cred -Force | Out-Null
try {
  if ($Scope -eq 'single' -and $HostName) {
    Write-Output $HostName
    return
  }
  if ($Scope -eq 'cluster' -and $Cluster) {
    $clusterObj = Get-Cluster -Name $Cluster -ErrorAction Stop
    $hosts = Get-VMHost -Location $clusterObj
  } else {
    $hosts = Get-VMHost
  }
  foreach ($vmHost in $hosts) {
    Write-Output $vmHost.Name
  }
} finally {
  Disconnect-VIServer -Server $env:VISERVER -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8") as tmp:
            tmp.write(script)
            script_path = tmp.name

        env = self._vcenter_env(vcenter)
        cmd = [
            "pwsh",
            "-NoProfile",
            "-File",
            script_path,
            "-Cluster",
            job.esxi_cluster or "",
            "-HostName",
            job.esxi_host or "",
            "-Scope",
            job.esxi_scope if job.esxi_scope != "all_hosts" else "all",
        ]
        try:
            result = self._run_command(cmd, env=env)
            if result.returncode != 0:
                detail = self._format_command_output(result)
                logger.error("Host enumeration failed: %s", detail)
                if job.esxi_host and self._is_valid_host_label(job.esxi_host):
                    return [job.esxi_host.strip()], None
                return [], detail

            hosts = [
                line.strip()
                for line in result.stdout.splitlines()
                if self._is_valid_host_label(line)
            ]
            if not hosts:
                detail = self._format_command_output(result)
                logger.error("No valid ESXi hostnames parsed: %s", detail)
                return [], detail or "No ESXi hosts returned from vCenter"
            return hosts, None
        finally:
            Path(script_path).unlink(missing_ok=True)

    def execute_scan(
        self,
        job: ScanJob,
        vcenter: VCenterConnection,
        *,
        job_id: int | None = None,
        on_result=None,
    ) -> ScanExecutionResult:
        from app.services.scan_progress import is_cancelled, parse_selected_targets, update_progress

        results: list[ScanRunResult] = []
        jid = job_id or job.id
        selected = parse_selected_targets(job.selected_targets_json)

        steps: list[tuple[str, str, str | None]] = []
        if job.scan_vcenter_product or selected.get("scan_vcenter_product"):
            steps.append(("vcenter_product", vcenter.hostname, None))
        if job.scan_vcenter_appliance or selected.get("scan_vcenter_appliance"):
            steps.append(("vcenter_appliance", vcenter.hostname, None))

        esxi_hosts: list[str] = list(selected.get("esxi_hosts") or [])
        if not esxi_hosts and job.scan_esxi:
            if job.esxi_scope == "single" and job.esxi_host:
                esxi_hosts = [job.esxi_host.strip()]
            else:
                esxi_hosts, enum_error = self._list_esxi_hosts(vcenter, job)
                if not esxi_hosts:
                    return ScanExecutionResult(
                        error=enum_error or "Could not enumerate ESXi hosts",
                        results=[
                            ScanRunResult(
                                target_type=ScanTargetType.ESXI.value,
                                target_name="esxi-enumeration",
                                status=ScanStatus.FAILED.value,
                                summary=enum_error,
                            )
                        ],
                    )
        for host in esxi_hosts:
            steps.append(("esxi", host, None))

        vm_names: list[str] = list(selected.get("vms") or [])
        if job.scan_vms or vm_names:
            if vm_names:
                for vm in vm_names:
                    steps.append(("vm", vm, vm))
            else:
                steps.append(("vm", "all-vms", None))

        update_progress(jid, message="Preparing scan...", current=0, total=max(len(steps), 1))

        total_steps = len(steps)
        try:
            step_num = 0
            for step_type, target_name, vm_name in steps:
                if is_cancelled(jid):
                    return ScanExecutionResult(
                        error="Scan cancelled by user",
                        results=results,
                    )

                step_num += 1
                if step_type == "vcenter_product":
                    update_progress(
                        jid,
                        message=f"Scanning vCenter product controls on {target_name}...",
                        current=step_num - 1,
                        total=total_steps,
                    )
                    result = self._run_inspec_powercli(
                        "vcenter",
                        target_name,
                        ScanTargetType.VCENTER_PRODUCT.value,
                        job,
                        vcenter,
                    )
                elif step_type == "vcenter_appliance":
                    update_progress(
                        jid,
                        message=f"Scanning vCenter appliance (SSH) on {target_name}...",
                        current=step_num - 1,
                        total=total_steps,
                    )
                    result = self._run_inspec_ssh_appliance(job, vcenter)
                elif step_type == "esxi":
                    update_progress(
                        jid,
                        message=f"Scanning ESXi host {target_name} (STIG profile)...",
                        current=step_num - 1,
                        total=total_steps,
                    )
                    result = self._run_inspec_powercli(
                        "esx",
                        target_name,
                        ScanTargetType.ESXI.value,
                        job,
                        vcenter,
                        {
                            "esx_vmhostName": target_name,
                            "esx_allHosts": False,
                            "esx_cluster": "",
                        },
                    )
                elif step_type == "vm":
                    label = vm_name or "all virtual machines"
                    update_progress(
                        jid,
                        message=f"Scanning VM {label} (STIG profile)...",
                        current=step_num - 1,
                        total=total_steps,
                    )
                    overrides = {
                        "vm_allvms": vm_name is None,
                        "vm_Name": vm_name or "",
                        "vm_cluster": job.esxi_cluster or "",
                    }
                    result = self._run_inspec_powercli(
                        "vm",
                        target_name,
                        ScanTargetType.VM.value,
                        job,
                        vcenter,
                        overrides,
                    )
                else:
                    continue

                results.append(result)
                update_progress(
                    jid,
                    message=f"Completed {step_type}: {target_name}",
                    current=step_num,
                    total=total_steps,
                )
                if on_result:
                    on_result(result)

            if not results:
                return ScanExecutionResult(
                    error="No scan targets selected",
                    results=results,
                )

            update_progress(
                jid,
                message="Scan finished",
                current=total_steps,
                total=total_steps,
            )
            return ScanExecutionResult(results=results)
        except subprocess.TimeoutExpired:
            return ScanExecutionResult(error="Scan timed out", results=results)
        except Exception as exc:
            logger.exception("Scan failed")
            return ScanExecutionResult(error=str(exc), results=results)
