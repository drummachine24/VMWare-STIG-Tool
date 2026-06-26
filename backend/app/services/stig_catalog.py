import json
import logging
from pathlib import Path

from app.config import Settings, get_settings
from app.services.scan_engine import ScanEngine

logger = logging.getLogger(__name__)

# Fallback titles if metadata files are missing (Y25M09-srg)
_DEFAULT_GUIDES = {
    "vcenter_product": "VMware Cloud Foundation 9.x Application vCenter Server STIG Readiness Guide",
    "esxi": "VMware Cloud Foundation 9.x ESX STIG Readiness Guide",
    "vm": "VMware Cloud Foundation 9.x Virtual Machine STIG Readiness Guide",
    "vcsa": [
        "VMware Cloud Foundation 9.x vCenter Server Appliance VAMI Service STIG Readiness Guide",
        "VMware Cloud Foundation 9.x vCenter Server Appliance PostgreSQL Service STIG Readiness Guide",
        "VMware Cloud Foundation 9.x vCenter Server Appliance Envoy Service STIG Readiness Guide",
        "VMware Cloud Foundation 9.x Photon OS 5.0 STIG Readiness Guide",
    ],
}


def _guide_titles(metadata_path: Path, name_contains: str | None = None) -> list[str]:
    if not metadata_path.exists():
        return []
    try:
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read STIG metadata %s: %s", metadata_path, exc)
        return []
    titles: list[str] = []
    for profile in data.get("profiles", []):
        name = profile.get("name", "")
        title = profile.get("title") or name
        if name_contains and name_contains.lower() not in name.lower():
            continue
        if title and title not in titles:
            titles.append(title)
    return titles


def get_stig_scan_catalog(settings: Settings | None = None) -> dict:
    """Catalog of scan types → STIG Readiness Guide titles (from profile metadata)."""
    engine = ScanEngine(settings or get_settings())

    vcenter_guides = _guide_titles(engine.metadata_path(), "vCenter Server") or [
        _DEFAULT_GUIDES["vcenter_product"]
    ]
    esxi_guides = _guide_titles(engine.metadata_path(), "ESX") or [_DEFAULT_GUIDES["esxi"]]
    vm_guides = _guide_titles(engine.metadata_path(), "Virtual Machine") or [_DEFAULT_GUIDES["vm"]]
    vcsa_guides = _guide_titles(engine.vcsa_metadata_path()) or _DEFAULT_GUIDES["vcsa"]

    return {
        "vcenter_product": {
            "label": "vCenter product",
            "transport": "PowerCLI → vCenter API",
            "profile": "vsphere/vcenter/",
            "guides": vcenter_guides,
        },
        "esxi": {
            "label": "ESXi host",
            "transport": "PowerCLI → vCenter API",
            "profile": "vsphere/esx/",
            "guides": esxi_guides,
        },
        "vm": {
            "label": "Virtual machine",
            "transport": "PowerCLI → vCenter API",
            "profile": "vsphere/vm/",
            "guides": vm_guides,
        },
        "vcsa_appliance": {
            "label": "VCSA appliance",
            "transport": "SSH → appliance OS",
            "profile": "vmware-cloud-foundation-vcsa-stig-baseline",
            "guides": vcsa_guides,
        },
    }


def build_stig_preview(
    selections: dict,
    *,
    scan_esxi: bool = False,
    scan_vms: bool = False,
    scan_vcenter_product: bool = False,
    scan_vcenter_appliance: bool = False,
    esxi_scope: str = "all_hosts",
    esxi_cluster: str = "",
    esxi_host: str = "",
    vcenter_hostname: str = "",
    settings: Settings | None = None,
) -> dict:
    """Build scan steps and STIG guide list from UI selections."""
    catalog = get_stig_scan_catalog(settings)
    steps: list[dict] = []
    guide_set: dict[str, int] = {}

    def add_guides(guide_list: list[str], count: int = 1) -> None:
        for guide in guide_list:
            guide_set[guide] = guide_set.get(guide, 0) + count

    product = selections.get("scan_vcenter_product") or scan_vcenter_product
    appliance = selections.get("scan_vcenter_appliance") or scan_vcenter_appliance
    esxi_hosts: list[str] = list(selections.get("esxi_hosts") or [])
    vms: list[str] = list(selections.get("vms") or [])
    tree_mode = bool(selections)

    if product:
        cat = catalog["vcenter_product"]
        steps.append(
            {
                "target": vcenter_hostname or "vCenter",
                "type": cat["label"],
                "transport": cat["transport"],
                "profile": cat["profile"],
                "guides": cat["guides"],
            }
        )
        add_guides(cat["guides"])

    if appliance:
        cat = catalog["vcsa_appliance"]
        steps.append(
            {
                "target": vcenter_hostname or "VCSA",
                "type": cat["label"],
                "transport": cat["transport"],
                "profile": cat["profile"],
                "guides": cat["guides"],
            }
        )
        add_guides(cat["guides"])

    if esxi_hosts:
        cat = catalog["esxi"]
        for host in esxi_hosts:
            steps.append(
                {
                    "target": host,
                    "type": cat["label"],
                    "transport": cat["transport"],
                    "profile": cat["profile"],
                    "guides": cat["guides"],
                }
            )
        add_guides(cat["guides"], len(esxi_hosts))
    elif scan_esxi and not tree_mode:
        scope_label = {
            "all_hosts": "all hosts in vCenter (enumerated at scan time)",
            "cluster": f"hosts in cluster '{esxi_cluster}'" if esxi_cluster else "cluster (name required)",
            "single": esxi_host or "single host (name required)",
        }.get(esxi_scope, esxi_scope)
        cat = catalog["esxi"]
        steps.append(
            {
                "target": scope_label,
                "type": cat["label"],
                "transport": cat["transport"],
                "profile": cat["profile"],
                "guides": cat["guides"],
                "estimated": True,
            }
        )
        add_guides(cat["guides"])

    if vms:
        cat = catalog["vm"]
        for vm in vms:
            steps.append(
                {
                    "target": vm,
                    "type": cat["label"],
                    "transport": cat["transport"],
                    "profile": cat["profile"],
                    "guides": cat["guides"],
                }
            )
        add_guides(cat["guides"], len(vms))
    elif scan_vms and not tree_mode:
        cat = catalog["vm"]
        steps.append(
            {
                "target": "all virtual machines",
                "type": cat["label"],
                "transport": cat["transport"],
                "profile": cat["profile"],
                "guides": cat["guides"],
                "estimated": True,
            }
        )
        add_guides(cat["guides"])

    guides_summary = [
        {"title": title, "audit_count": count} for title, count in sorted(guide_set.items())
    ]

    return {
        "step_count": len(steps),
        "steps": steps,
        "guides": guides_summary,
        "empty": len(steps) == 0,
    }
