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
NTP_SERVERS_LINE = re.compile(r"^(\s*ntpServers\s*=\s*)@\(.*\)(.*)$", re.MULTILINE | re.IGNORECASE)
HELPERS_ZIP_GLOB = "VMware.VCF.STIG.Helpers-*.zip"
NTP_CONTROL_KEY = "VCFE9X000121"


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

    def _parse_ntp_servers(self, scan_inputs_yaml: str | None = None) -> list[str]:
        servers: list[str] = []
        if scan_inputs_yaml:
            try:
                import yaml

                parsed = yaml.safe_load(scan_inputs_yaml) or {}
                if isinstance(parsed, dict):
                    raw = parsed.get("esx_ntpServers") or parsed.get("vcenter_ntpServers")
                    if isinstance(raw, list):
                        servers = [str(item).strip() for item in raw if str(item).strip()]
                    elif isinstance(raw, str) and raw.strip():
                        servers = [part.strip() for part in raw.split(",") if part.strip()]
            except Exception as exc:
                logger.warning("Could not parse scan inputs for NTP servers: %s", exc)

        if not servers and self.settings.remediation_esxi_ntp_servers.strip():
            servers = [
                part.strip()
                for part in self.settings.remediation_esxi_ntp_servers.split(",")
                if part.strip()
            ]
        return servers

    def _format_ps_string_array(self, values: list[str]) -> str:
        parts: list[str] = []
        for value in values:
            escaped = value.replace("`", "``").replace('"', '`"')
            parts.append(f'"{escaped}"')
        return "@(" + ", ".join(parts) + ")"

    def _inject_envstig_settings(
        self,
        content: str,
        *,
        vcf_control_id: str,
        ntp_servers: list[str],
    ) -> str:
        if _control_key(vcf_control_id) != NTP_CONTROL_KEY or not ntp_servers:
            return content

        ps_array = self._format_ps_string_array(ntp_servers)

        def repl(match: re.Match) -> str:
            return f"{match.group(1)}{ps_array}{match.group(2)}"

        updated, count = NTP_SERVERS_LINE.subn(repl, content, count=1)
        if count == 0:
            raise ValueError(
                "Could not locate envstigsettings.ntpServers in remediation variables file"
            )
        return updated

    def _patch_esxi_script(content: str) -> str:
        """Broadcom NTP block assumes ntpconfig.server is never null."""
        content = content.replace(
            'If($currentntpservers.count -eq "0"){',
            "If(-not $currentntpservers -or @($currentntpservers).Count -eq 0){",
        )
        content = content.replace(
            "If($currentntpservers.count -ne 0){",
            "If($currentntpservers -and @($currentntpservers).Count -ne 0){",
        )
        return content

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
        *,
        vcf_control_id: str,
        scan_inputs_yaml: str | None = None,
        strict_ntp: bool = True,
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

        if enabled_rule_key.upper() == NTP_CONTROL_KEY:
            ntp_servers = self._parse_ntp_servers(scan_inputs_yaml)
            if ntp_servers:
                updated = self._inject_envstig_settings(
                    updated,
                    vcf_control_id=vcf_control_id,
                    ntp_servers=ntp_servers,
                )
            elif strict_ntp:
                raise ValueError(
                    "VCFE-9X-000121 requires authorized NTP servers. Set REMEDIATION_ESXI_NTP_SERVERS "
                    "in the environment, esx_ntpServers in scan inputs, or edit ntpServers in the "
                    "remediation variables editor before running."
                )
        return updated

    def _validate_variables_content(self, content: str, enabled_rule_key: str) -> None:
        if not content or not content.strip():
            raise ValueError("Remediation variables file cannot be empty")
        if len(content) > 512_000:
            raise ValueError("Remediation variables file is too large")
        if "\x00" in content:
            raise ValueError("Remediation variables file contains invalid characters")
        if "$rulesenabled" not in content:
            raise ValueError("Remediation variables file must define $rulesenabled")
        if not re.search(rf"{re.escape(enabled_rule_key)}\s*=\s*\$true", content, re.IGNORECASE):
            raise ValueError(
                f"Remediation variables file must keep {enabled_rule_key} enabled ($true)"
            )

    def generate_variables_content(
        self,
        *,
        target_type: str,
        vcf_control_id: str,
        scan_inputs_yaml: str | None = None,
        custom_content: str | None = None,
        strict_ntp: bool | None = None,
    ) -> str:
        rule_key = _control_key(vcf_control_id)
        if not rule_key:
            raise ValueError(f"Invalid VCF control id: {vcf_control_id}")

        if custom_content is not None:
            self._validate_variables_content(custom_content, rule_key)
            return custom_content

        bundle = _resolve_powercli_bundle(self.catalog.powercli_dir, target_type)
        if not bundle:
            raise FileNotFoundError(
                f"No PowerCLI remediation bundle for target type {target_type}"
            )
        variables_path: Path | None = bundle.get("variables_path")
        if not variables_path or not variables_path.exists():
            raise FileNotFoundError("Remediation variables file not found")

        ntp_strict = strict_ntp if strict_ntp is not None else True
        return self._build_variables_override(
            variables_path,
            rule_key,
            vcf_control_id=vcf_control_id,
            scan_inputs_yaml=scan_inputs_yaml,
            strict_ntp=ntp_strict,
        )

    def preview_remediation(
        self,
        *,
        target_type: str,
        vcf_control_id: str,
        scan_inputs_yaml: str | None = None,
    ) -> dict:
        bundle = _resolve_powercli_bundle(self.catalog.powercli_dir, target_type)
        if not bundle:
            raise FileNotFoundError(
                f"No PowerCLI remediation bundle for target type {target_type}"
            )
        lookup = self.catalog.lookup(target_type, vcf_control_id)
        content = self.generate_variables_content(
            target_type=target_type,
            vcf_control_id=vcf_control_id,
            scan_inputs_yaml=scan_inputs_yaml,
            strict_ntp=False,
        )
        if _control_key(vcf_control_id) == NTP_CONTROL_KEY and "ntpServers = @()" in content:
            notes = (
                "Edit the $envstigsettings section for environment-specific values "
                "(for example ntpServers, allowedips, lockdownExceptionUsers, esxAdminsGroup). "
                "Only the selected control remains enabled in $rulesenabled. "
                "For VCFE-9X-000121, set ntpServers to your authorized NTP server list before running."
            )
        else:
            notes = (
                "Edit the $envstigsettings section for environment-specific values "
                "(for example ntpServers, allowedips, lockdownExceptionUsers, esxAdminsGroup). "
                "Only the selected control remains enabled in $rulesenabled."
            )
        return {
            "vcf_control_id": vcf_control_id,
            "script_name": bundle["script_path"].name,
            "variables_name": bundle.get("variables_path").name if bundle.get("variables_path") else "",
            "variables_hint": lookup.get("variables_hint") or "",
            "variables_content": content,
            "notes": notes,
        }

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

                # Legacy helpers still referenced in some upstream remediation blocks.
                function global:Write-ToConsole {{
                    param([string]$Details)
                    $LogDate = Get-Date -Format T
                    Write-Host "$($LogDate) $Details"
                }}
                function global:Write-ToConsoleRed {{
                    param([string]$Details)
                    $LogDate = Get-Date -Format T
                    Write-Host "$($LogDate) $Details" -ForegroundColor Red
                }}
                function global:Write-ToConsoleBlue {{
                    param([string]$Details)
                    $LogDate = Get-Date -Format T
                    Write-Host "$($LogDate) $Details" -ForegroundColor Blue
                }}

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
        scan_inputs_yaml: str | None = None,
        variables_override: str | None = None,
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
            self.generate_variables_content(
                target_type=target_type,
                vcf_control_id=vcf_control_id,
                scan_inputs_yaml=scan_inputs_yaml,
                custom_content=variables_override,
            ),
            encoding="utf-8",
        )

        local_script_path = work_dir / script_path.name
        shutil.copy2(script_path, local_script_path)
        if target_type == ScanTargetType.ESXI.value:
            patched = self._patch_esxi_script(local_script_path.read_text(encoding="utf-8", errors="replace"))
            local_script_path.write_text(patched, encoding="utf-8")

        helpers_manifest = self._ensure_helpers(script_path.parent, work_dir)
        launcher_path = work_dir / launcher_name
        launcher_path.write_text(
            self._launcher_script(
                script_path=local_script_path,
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
