import logging
import re
from functools import lru_cache
from pathlib import Path

from app.config import Settings, get_settings
from app.models import ScanTargetType
from app.services.remediation_catalog import RemediationCatalog, _control_key

logger = logging.getLogger(__name__)

CONTROL_ID_RE = re.compile(
    r"(VCFE|VCFV|VCFH|VCFA|PHTN|VCEM|VCUI|VCST|VCLU|VCEN|VCPG|VCRP|VAMI)-[\dA-Z.]+-[\d]+",
    re.IGNORECASE,
)
TAG_RE = re.compile(r"^\s*tag\s+(\w+):\s*['\"]([^'\"]+)['\"]", re.MULTILINE)


def _relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _normalize_vcf_control_id(value: str) -> str:
    match = CONTROL_ID_RE.search(value or "")
    return match.group(0).upper() if match else ""


@lru_cache(maxsize=32)
def _load_inspec_controls(root: str) -> dict[str, dict]:
    base = Path(root)
    if not base.exists():
        return {}
    controls: dict[str, dict] = {}
    for rb_file in base.rglob("controls/*.rb"):
        try:
            content = rb_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cid_match = re.search(r"control\s+['\"]([^'\"]+)['\"]", content)
        if not cid_match:
            continue
        control_id = cid_match.group(1).upper()
        title_match = re.search(r"title\s+['\"]([^'\"]+)['\"]", content)
        desc_match = re.search(
            r"desc\s+(?:<<~(?:DESC|EOF)|['\"])(.*?)(?:\1|DESC|EOF)",
            content,
            re.S,
        )
        desc = desc_match.group(1).strip() if desc_match else ""
        controls[control_id] = {
            "control_id": control_id,
            "title": title_match.group(1) if title_match else control_id,
            "desc": desc,
            "source": _relative_path(rb_file, base),
        }
    return controls


@lru_cache(maxsize=32)
def _load_inspec_crosswalk(root: str) -> dict[str, str]:
    """Map SV-/V- rule ids and tag aliases to VCF control ids."""
    base = Path(root)
    if not base.exists():
        return {}
    crosswalk: dict[str, str] = {}

    def add_alias(alias: str, control_id: str) -> None:
        if not alias:
            return
        crosswalk[alias.upper()] = control_id
        crosswalk[_control_key(alias)] = control_id

    for rb_file in base.rglob("controls/*.rb"):
        try:
            content = rb_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cid_match = re.search(r"control\s+['\"]([^'\"]+)['\"]", content)
        if not cid_match:
            continue
        control_id = _normalize_vcf_control_id(cid_match.group(1)) or cid_match.group(1).upper()
        add_alias(control_id, control_id)
        add_alias(rb_file.stem, control_id)
        for tag_match in TAG_RE.finditer(content):
            add_alias(tag_match.group(2), control_id)

    return crosswalk


def resolve_vcf_control_id(
    crosswalk: dict[str, str],
    *values: str,
) -> str:
    for value in values:
        if not value:
            continue
        direct = _normalize_vcf_control_id(value)
        if direct:
            return direct
        upper = value.upper()
        if upper in crosswalk:
            return crosswalk[upper]
        keyed = _control_key(value)
        if keyed in crosswalk:
            return crosswalk[keyed]
    return ""


class RemediationIndex:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.profile_root = Path(self.settings.stig_profiles_path) / self.settings.vcf_profile_base
        self.baseline = self.profile_root / self.settings.vcf_baseline_profile
        self.vcsa = self.profile_root / self.settings.vcf_vcsa_profile
        self.catalog = RemediationCatalog(self.settings)

    def _inspec_root_for_target(self, target_type: str) -> Path | None:
        if target_type == ScanTargetType.ESXI.value:
            return self.baseline / "esx"
        if target_type == ScanTargetType.VM.value:
            return self.baseline / "vm"
        if target_type == ScanTargetType.VCENTER_PRODUCT.value:
            return self.baseline / "vcenter"
        if target_type == ScanTargetType.VCENTER_APPLIANCE.value:
            return self.vcsa
        return None

    def enrich_item(self, target_type: str, control_id: str, rule_id: str) -> dict:
        inspec_root = self._inspec_root_for_target(target_type)
        inspec_data = _load_inspec_controls(str(inspec_root)) if inspec_root else {}
        crosswalk = _load_inspec_crosswalk(str(inspec_root)) if inspec_root else {}

        vcf_control_id = resolve_vcf_control_id(crosswalk, control_id, rule_id)
        lookup_ids = [vcf_control_id, control_id, rule_id]

        inspec_match = {}
        for cid in lookup_ids:
            norm = (cid or "").upper()
            if norm in inspec_data:
                inspec_match = inspec_data[norm]
                break
            match = CONTROL_ID_RE.search(cid or "")
            if match and match.group(0).upper() in inspec_data:
                inspec_match = inspec_data[match.group(0).upper()]
                break

        remediation = self.catalog.lookup(
            target_type,
            vcf_control_id or control_id,
            rule_id,
        )
        if vcf_control_id:
            remediation["vcf_control_id"] = vcf_control_id

        return {
            "inspec_title": inspec_match.get("title", ""),
            "inspec_desc": inspec_match.get("desc", ""),
            "inspec_source": inspec_match.get("source", ""),
            "remediation": remediation,
            "remediation_script": remediation.get("snippet") or inspec_match.get("desc", ""),
            "remediation_source": remediation.get("script_path") or remediation.get("docs", ""),
            "remediation_note": remediation.get("docs", ""),
            "remediation_run_command": remediation.get("run_command", ""),
            "remediation_github_url": remediation.get("github_script_url", ""),
            "github_repo": remediation.get("github_repo", ""),
        }

    def enrich_checklist(self, target_type: str, items: list) -> list[dict]:
        enriched = []
        for item in items:
            data = item.__dict__ if hasattr(item, "__dict__") else dict(item)
            extra = self.enrich_item(
                target_type,
                str(data.get("control_id") or data.get("rule_id") or ""),
                str(data.get("rule_id") or ""),
            )
            data.update(extra)
            if extra.get("inspec_title") and not data.get("rule_title"):
                data["rule_title"] = extra["inspec_title"]
            if not data.get("remediation_script"):
                data["remediation_script"] = extra.get("inspec_desc") or extra.get("remediation_note", "")
            enriched.append(data)
        return enriched
