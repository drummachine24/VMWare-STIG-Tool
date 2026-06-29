import logging
import os
import re
import shutil
import subprocess
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings, get_settings
from app.models import ScanTargetType, VCenterConnection
from app.services.crypto import decrypt_secret
from app.services.remediation_catalog import RemediationCatalog, _control_key, _resolve_powercli_bundle

logger = logging.getLogger(__name__)

RULE_ENABLED_LINE = re.compile(r"^(\s*)(VCF[A-Z0-9]+)\s*=\s*\$(true|false)", re.IGNORECASE | re.MULTILINE)
HELPERS_ZIP_GLOB = "VMware.VCF.STIG.Helpers-*.zip"


class RemediationEngine:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.catalog = RemediationCatalog(self.settings)
        self.reports_dir = Path(self.settings.reports_path)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _vcenter_env(self, vcenter: VCenterConnection) -> dict[str, str]:
        env = os.environ.copy()
        env["VISERVER"] = vcenter.hostname
        env["VISERVER_USERNAME"] = vcenter.api_username
        env["VISERVER_PASSWORD"] = decrypt_secret(vcenter.api_password_encrypted)
        env["NO_COLOR"] = "true"
        return env

    def _ensure_helpers(self, powercli_dir: Path, work_dir: Path) -> Path:
        zips = sorted(powercli_dir.glob(HELPERS_ZIP_GLOB))
        if not zips:
            raise FileNotFoundError(
                f"VMware.VCF.STIG.Helpers zip not found under {powercli_dir}"
            )
        module_dir = work_dir / "helpers"
        if module_dir.exists():
            shutil.rmtree(module_dir)
        module_dir.mkdir(parents=True, exist_ok=True)
        shutil.unpack_archive(str(zips[0]), str(module_dir))

        preferred = sorted(module_dir.rglob("VMware.VCF.STIG.Helpers.psd1"))
        psd1 = preferred[0] if preferred else None
        if not psd1:
            all_psd1 = sorted(module_dir.rglob("*.psd1"))
            if not all_psd1:
                raise FileNotFoundError(f"No module manifest found in {zips[0]}")
            psd1 = all_psd1[0]

        psm1 = psd1.with_suffix(".psm1")
        if not psm1.exists():
            sibling_psm1 = next(psd1.parent.glob("*.psm1"), None)
            if not sibling_psm1:
                extracted = sorted(
                    str(path.relative_to(module_dir))
                    for path in module_dir.rglob("*")
                    if path.is_file()
                )
                preview = "\n".join(extracted[:40]) or "(no files extracted)"
                raise FileNotFoundError(
                    f"Helpers module manifest {psd1.name} has no companion .psm1. "
                    f"Check {zips[0]} is intact (not a Git LFS pointer). Extracted:\n{preview}"
                )

        return psd1

    def _build_global_override(
        self,
        vcenter_hostname: str,
        target_type: str,
        target_name: str,
        report_path: Path,
    ) -> str:
        lines = [
            "# STIG Tool generated global variables",
            f'$ReportPath = "{report_path.as_posix()}"',
            f'$reportpath = "{report_path.as_posix()}"',
            f'$vcenter = "{vcenter_hostname}"',
            '$hostname = ""',
            '$cluster = ""',
            '$vmname = ""',
            '$allvms = $false',
        ]
        if target_type == ScanTargetType.VM.value:
            lines.append(f'$vmname = "{target_name}"')
            lines.append("$allvms = $false")
        elif target_type == ScanTargetType.ESXI.value:
            lines.append(f'$hostname = "{target_name}"')
        elif target_type == ScanTargetType.VCENTER_PRODUCT.value:
            lines.append(f'$vcenter = "{vcenter_hostname}"')
        return "\n".join(lines) + "\n"

    def _build_variables_override(
        self,
        variables_path: Path,
        enabled_rule_key: str,
    ) -> str:
        content = variables_path.read_text(encoding="utf-8", errors="replace")

        def repl(match: re.Match) -> str:
            key = match.group(2).upper()
            value = "$true" if key == enabled_rule_key.upper() else "$false"
            return f"{match.group(1)}{key} = {value}"

        updated = RULE_ENABLED_LINE.sub(repl, content)
        if updated == content:
            raise ValueError(
                f"Could not locate rulesenabled entry for {enabled_rule_key} in {variables_path.name}"
            )
        return updated

    def _launcher_script(
        self,
        *,
        script_path: Path,
        global_file: str,
        variables_file: str,
        helpers_manifest: Path,
    ) -> str:
        return (
            textwrap.dedent(
                f"""
                $ErrorActionPreference = "Stop"
                Import-Module "{helpers_manifest.as_posix()}" -Force
                Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                $secure = ConvertTo-SecureString $env:VISERVER_PASSWORD -AsPlainText -Force
                $vccred = New-Object System.Management.Automation.PSCredential($env:VISERVER_USERNAME, $secure)
                & "{script_path.as_posix()}" -vccred $vccred -NoSafetyChecks `
                  -GlobalVarsFile "{global_file}" `
                  -RemediationVarsFile "{variables_file}"
                exit $LASTEXITCODE
                """
            ).strip()
            + "\n"
        )

    def run_control(
        self,
        vcenter: VCenterConnection,
        target_type: str,
        target_name: str,
        vcf_control_id: str,
        remediation_job_id: int,
    ) -> dict:
        if self.settings.dry_run:
            return {
                "status": "completed",
                "message": f"DRY_RUN: would remediate {vcf_control_id} on {target_name}",
                "log_path": None,
            }

        bundle = _resolve_powercli_bundle(self.catalog.powercli_dir, target_type)
        if not bundle:
            raise FileNotFoundError(
                f"No PowerCLI remediation bundle for target type {target_type}"
            )

        script_path: Path = bundle["script_path"]
        variables_path: Path | None = bundle.get("variables_path")
        if not variables_path or not variables_path.exists():
            raise FileNotFoundError("Remediation variables file not found")

        rule_key = _control_key(vcf_control_id)
        if not rule_key:
            raise ValueError(f"Invalid VCF control id: {vcf_control_id}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = re.sub(r"[^\w\-.]+", "_", target_name)[:48]
        work_dir = self.reports_dir / "remediation" / f"job{remediation_job_id}-{slug}-{timestamp}"
        work_dir.mkdir(parents=True, exist_ok=True)
        report_path = work_dir / "reports"
        report_path.mkdir(parents=True, exist_ok=True)

        global_name = "stigtool_global.ps1"
        variables_name = "stigtool_variables.ps1"
        launcher_name = "stigtool_launcher.ps1"
        (work_dir / global_name).write_text(
            self._build_global_override(vcenter.hostname, target_type, target_name, report_path),
            encoding="utf-8",
        )
        (work_dir / variables_name).write_text(
            self._build_variables_override(variables_path, rule_key),
            encoding="utf-8",
        )

        helpers_manifest = self._ensure_helpers(script_path.parent, work_dir)
        launcher_path = work_dir / launcher_name
        launcher_path.write_text(
            self._launcher_script(
                script_path=script_path,
                global_file=global_name,
                variables_file=variables_name,
                helpers_manifest=helpers_manifest,
            ),
            encoding="utf-8",
        )

        log_path = work_dir / "remediation.log"
        env = self._vcenter_env(vcenter)
        cmd = ["pwsh", "-NoProfile", "-File", str(launcher_path)]
        logger.info("Running remediation %s on %s: %s", vcf_control_id, target_name, cmd)

        with log_path.open("w", encoding="utf-8") as log_file:
            log_file.write(
                f"Control: {vcf_control_id}\nTarget: {target_name}\nType: {target_type}\n\n"
            )
            proc = subprocess.run(
                cmd,
                cwd=work_dir,
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.settings.scan_timeout_seconds,
                check=False,
            )

        tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        if proc.returncode != 0:
            return {
                "status": "failed",
                "message": f"Remediation exited with code {proc.returncode}",
                "log_path": str(log_path),
                "output_tail": tail,
            }

        message = (
            "Remediation completed"
            if "Remediation Complete" in tail
            else "Remediation finished; review log for details"
        )
        return {
            "status": "completed",
            "message": message,
            "log_path": str(log_path),
            "output_tail": tail,
        }
