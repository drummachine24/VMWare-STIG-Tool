import logging
import re
from functools import lru_cache
from pathlib import Path

from app.config import Settings, get_settings
from app.models import ScanTargetType

logger = logging.getLogger(__name__)

GITHUB_REPO = "https://github.com/vmware/dod-compliance-and-automation"
GITHUB_BLOB = f"{GITHUB_REPO}/blob/master"
GITHUB_SEARCH = "https://github.com/search?q=repo%3Avmware%2Fdod-compliance-and-automation+remediation&type=code"

CONTROL_ID_RE = re.compile(
    r"(VCFE|VCFV|VCFH|VCFA|PHTN|VCEM|VCUI|VCST|VCLU|VCEN|VCPG|VCRP|VAMI)-[\dA-Z.]+-[\d]+",
    re.IGNORECASE,
)
SECTION_HEADER_RE = re.compile(
    r"^#\s*((?:VCFE|VCFV|VCFH|VCFA|PHTN|VCEM|VCUI|VCST|VCLU|VCEN|VCPG|VCRP|VAMI)-[\dA-Z.]+-[\d]+)\b",
    re.MULTILINE | re.IGNORECASE,
)
VARIABLE_LINE_RE = re.compile(
    r"#\s*((?:VCFE|VCFV|VCFH|VCFA|PHTN|VCEM|VCUI|VCST|VCLU|VCEN|VCPG|VCRP|VAMI)-[\dA-Z.]+-[\d]+)\s*(.*)$",
    re.IGNORECASE,
)

POWERCLI_BUNDLE_PATTERNS = {
    ScanTargetType.ESXI.value: {
        "label": "ESXi hosts",
        "script_glob": "*ESX*_STIG_Remediation.ps1",
        "variables_glob": "*ESX*_STIG_Remediation_Variables.ps1",
    },
    ScanTargetType.VM.value: {
        "label": "Virtual machines",
        "script_glob": "*VM*_STIG_Remediation.ps1",
        "variables_glob": "*VM*_STIG_Remediation_Variables.ps1",
    },
    ScanTargetType.VCENTER_PRODUCT.value: {
        "label": "vCenter product",
        "script_glob": "*vCenter*_STIG_Remediation.ps1",
        "variables_glob": "*vCenter*_STIG_Remediation_Variables.ps1",
    },
}

GLOBAL_VARS_GLOB = "*_STIG_Global_Variables.ps1"
SCRIPT_EXCLUDE = ("Variables", "InSpec")


def _control_key(control_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", control_id or "").upper()


def _normalize_control_id(value: str) -> str:
    match = CONTROL_ID_RE.search(value or "")
    return match.group(0).upper() if match else (value or "").upper()


def _relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _find_powercli_file(powercli_dir: Path, pattern: str, *, exclude: tuple[str, ...] = ()) -> Path | None:
    for candidate in sorted(powercli_dir.glob(pattern)):
        if any(token in candidate.name for token in exclude):
            continue
        return candidate
    return None


def _resolve_powercli_bundle(powercli_dir: Path, target_type: str) -> dict | None:
    pattern = POWERCLI_BUNDLE_PATTERNS.get(target_type)
    if not pattern or not powercli_dir.exists():
        return None
    script_path = _find_powercli_file(powercli_dir, pattern["script_glob"], exclude=SCRIPT_EXCLUDE)
    variables_path = _find_powercli_file(powercli_dir, pattern["variables_glob"])
    if not script_path:
        return None
    global_path = _find_powercli_file(powercli_dir, GLOBAL_VARS_GLOB)
    return {
        "label": pattern["label"],
        "script_path": script_path,
        "variables_path": variables_path,
        "global_path": global_path,
        "run_command": f"./{script_path.name} -vccred $vccred",
    }


@lru_cache(maxsize=16)
def _load_ps1_sections(script_path: str) -> dict[str, str]:
    path = Path(script_path)
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    sections: dict[str, str] = {}
    matches = list(SECTION_HEADER_RE.finditer(text))
    for index, match in enumerate(matches):
        control_id = match.group(1).upper()
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        snippet = text[start:end].strip()
        sections[control_id] = snippet
        sections[_control_key(control_id)] = snippet
    return sections


@lru_cache(maxsize=16)
def _load_variable_hints(variables_path: str) -> dict[str, str]:
    path = Path(variables_path)
    if not path.exists():
        return {}
    hints: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = VARIABLE_LINE_RE.search(line)
        if not match:
            continue
        control_id = match.group(1).upper()
        hint = match.group(2).strip()
        if hint:
            hints[control_id] = hint
            hints[_control_key(control_id)] = hint
    return hints


@lru_cache(maxsize=4)
def _load_ansible_index(ansible_root: str, profile_root: str) -> dict[str, list[dict]]:
    root = Path(ansible_root)
    profile = Path(profile_root)
    if not root.exists():
        return {}
    index: dict[str, list[dict]] = {}

    def add_file(yml_file: Path) -> None:
        try:
            content = yml_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        for match in CONTROL_ID_RE.finditer(content):
            control_id = match.group(0).upper()
            entry = {
                "path": _relative_path(yml_file, root),
                "github_url": _github_blob_path(_relative_path(yml_file, profile)),
            }
            for key in (control_id, _control_key(control_id)):
                bucket = index.setdefault(key, [])
                if not any(x["path"] == entry["path"] for x in bucket):
                    bucket.append(entry)

    for pattern in ("*.yml", "*.yaml"):
        for yml_file in root.rglob(pattern):
            add_file(yml_file)
    return index


def _github_blob_path(profile_relative: str) -> str:
    return f"{GITHUB_BLOB}/{profile_relative.replace(chr(92), '/')}"


class RemediationCatalog:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.profile_root = Path(self.settings.stig_profiles_path) / self.settings.vcf_profile_base
        self.powercli_dir = self.profile_root / "powercli" / "vmware-cloud-foundation-stig-powercli-hardening"
        self.ansible_dir = self.profile_root / "ansible" / "vmware-cloud-foundation-stig-ansible-hardening"

    def sync_status(self) -> dict:
        pc_exists = self.powercli_dir.exists()
        ansible_exists = self.ansible_dir.exists()
        scripts: list[Path] = []
        if pc_exists:
            scripts = [
                p
                for p in self.powercli_dir.glob("*_STIG_Remediation.ps1")
                if not any(token in p.name for token in SCRIPT_EXCLUDE)
            ]
        return {
            "synced": pc_exists and len(scripts) >= 1,
            "powercli_dir_exists": pc_exists,
            "powercli_dir": str(self.powercli_dir),
            "remediation_scripts_found": len(scripts),
            "ansible_dir_exists": ansible_exists,
            "ansible_dir": str(self.ansible_dir),
            "profile_base": self.settings.vcf_profile_base,
            "setup_hint": "Run: bash scripts/setup-stig-profiles.sh ./stig-profiles",
        }

    def github_search_url(self) -> str:
        return GITHUB_SEARCH

    def list_assets(self) -> dict:
        powercli = []
        if self.powercli_dir.exists():
            for ps1 in sorted(self.powercli_dir.glob("*.ps1")):
                rel = _relative_path(ps1, self.profile_root)
                powercli.append(
                    {
                        "name": ps1.name,
                        "path": rel,
                        "github_url": _github_blob_path(rel),
                        "is_remediation": "Remediation" in ps1.name and "Variables" not in ps1.name,
                        "is_variables": "Remediation_Variables" in ps1.name,
                    }
                )

        ansible = []
        if self.ansible_dir.exists():
            for yml in sorted(list(self.ansible_dir.rglob("*.yml")) + list(self.ansible_dir.rglob("*.yaml"))):
                rel = _relative_path(yml, self.profile_root)
                ansible.append({"name": yml.name, "path": rel, "github_url": _github_blob_path(rel)})

        return {
            "github_repo": GITHUB_REPO,
            "github_search": self.github_search_url(),
            "profile_base": self.settings.vcf_profile_base,
            "sync_status": self.sync_status(),
            "powercli_dir": _relative_path(self.powercli_dir, self.profile_root) if self.powercli_dir.exists() else None,
            "ansible_dir": _relative_path(self.ansible_dir, self.profile_root) if self.ansible_dir.exists() else None,
            "powercli_scripts": powercli,
            "ansible_files": ansible[:200],
            "bundles": {
                key: {
                    "label": val["label"],
                    "script_glob": val["script_glob"],
                    "variables_glob": val["variables_glob"],
                }
                for key, val in POWERCLI_BUNDLE_PATTERNS.items()
            },
        }

    def lookup(self, target_type: str, control_id: str, rule_id: str = "") -> dict:
        normalized_ids = {_normalize_control_id(control_id), _normalize_control_id(rule_id)}
        normalized_ids.discard("")
        keys = {_control_key(i) for i in normalized_ids if i}

        bundle = _resolve_powercli_bundle(self.powercli_dir, target_type)
        ansible_index = _load_ansible_index(str(self.ansible_dir), str(self.profile_root))

        result = {
            "control_ids": sorted(normalized_ids),
            "github_repo": GITHUB_REPO,
            "github_search": self.github_search_url(),
            "type": "manual",
            "snippet": "",
            "variables_hint": "",
            "script_name": "",
            "script_path": "",
            "variables_name": "",
            "variables_path": "",
            "github_script_url": "",
            "github_variables_url": "",
            "run_command": "",
            "ansible_matches": [],
            "docs": "",
        }

        if bundle:
            script_path = bundle["script_path"]
            variables_path = bundle.get("variables_path")
            global_path = bundle.get("global_path")
            sections = _load_ps1_sections(str(script_path))
            hints = _load_variable_hints(str(variables_path)) if variables_path else {}

            snippet = ""
            var_hint = ""
            for key in keys | normalized_ids:
                if key in sections and not snippet:
                    snippet = sections[key]
                if key in hints and not var_hint:
                    var_hint = hints[key]

            if snippet or script_path.exists():
                result.update(
                    {
                        "type": "powercli",
                        "snippet": snippet,
                        "variables_hint": var_hint,
                        "script_name": script_path.name,
                        "script_path": _relative_path(script_path, self.profile_root),
                        "variables_name": variables_path.name if variables_path else "",
                        "variables_path": (
                            _relative_path(variables_path, self.profile_root) if variables_path else ""
                        ),
                        "github_script_url": _github_blob_path(_relative_path(script_path, self.profile_root)),
                        "github_variables_url": (
                            _github_blob_path(_relative_path(variables_path, self.profile_root))
                            if variables_path
                            else ""
                        ),
                        "run_command": bundle["run_command"],
                        "docs": (
                            f"Update {variables_path.name if variables_path else 'the variables file'} and "
                            f"{global_path.name if global_path else 'the global variables file'} in the PowerCLI "
                            f"hardening folder, then run the remediation script from {self.powercli_dir.name}."
                        ),
                    }
                )
                if global_path and global_path.exists():
                    result["global_variables_path"] = _relative_path(global_path, self.profile_root)
                    result["github_global_variables_url"] = _github_blob_path(
                        _relative_path(global_path, self.profile_root)
                    )
        elif POWERCLI_BUNDLE_PATTERNS.get(target_type) and not self.powercli_dir.exists():
            result["docs"] = (
                "Remediation scripts are not synced locally. Run "
                "bash scripts/setup-stig-profiles.sh ./stig-profiles on the host, then restart containers."
            )

        ansible_matches: list[dict] = []
        for key in keys | normalized_ids:
            ansible_matches.extend(ansible_index.get(key, []))
        if ansible_matches:
            result["type"] = "ansible" if result["type"] == "manual" else result["type"]
            result["ansible_matches"] = ansible_matches
            result["docs"] = (
                result.get("docs")
                or "VCSA and other appliance components are remediated with Ansible playbooks from vmware-cloud-foundation-stig-ansible-hardening."
            )

        if target_type == ScanTargetType.VCENTER_APPLIANCE.value and not ansible_matches:
            result["docs"] = (
                "VCSA appliance remediation uses Ansible under "
                f"{_relative_path(self.ansible_dir, self.profile_root) if self.ansible_dir.exists() else 'ansible/vmware-cloud-foundation-stig-ansible-hardening'}. "
                "See Broadcom VCF 9.x STIG remediation docs."
            )
            result["type"] = "ansible"

        return result
