import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import ScanResult, ScanTargetType
from app.services.remediation_index import (
    RemediationIndex,
    _load_inspec_crosswalk,
    resolve_vcf_control_id,
)
from app.services.result_parser import parse_scan_artifact

logger = logging.getLogger(__name__)

AGGREGATE_TARGETS = frozenset({"all-vms", "all-hosts", "esxi-enumeration"})


def _rule_matches(item_rule_id: str, item_control_id: str, rule_id: str, vcf_control_id: str) -> bool:
    candidates = {rule_id.upper(), vcf_control_id.upper()}
    candidates.discard("")
    item_values = {item_rule_id.upper(), item_control_id.upper()}
    if candidates & item_values:
        return True
    for value in (item_rule_id, item_control_id):
        resolved = resolve_vcf_control_id({}, value)
        if resolved and resolved.upper() in candidates:
            return True
    return False


def resolve_vcf_control_for_finding(
    target_type: str,
    rule_id: str,
    control_id: str,
) -> str:
    index = RemediationIndex()
    inspec_root = index._inspec_root_for_target(target_type)
    crosswalk = _load_inspec_crosswalk(str(inspec_root)) if inspec_root else {}
    return resolve_vcf_control_id(crosswalk, control_id, rule_id)


def finding_has_open_status(
    result: ScanResult,
    rule_id: str,
    vcf_control_id: str,
    control_id: str,
) -> bool:
    json_path = Path(result.json_path) if result.json_path else None
    ckl_path = Path(result.ckl_path) if result.ckl_path else None
    if not json_path and not ckl_path:
        return False
    parsed = parse_scan_artifact(json_path, ckl_path)
    for item in parsed.items:
        if item.status != "O":
            continue
        if _rule_matches(item.rule_id, item.control_id, rule_id, vcf_control_id):
            return True
    return False


def list_remediation_peers(
    db: Session,
    scan_job_id: int,
    source_result_id: int,
    rule_id: str,
    control_id: str = "",
    vcf_control_id: str = "",
) -> dict:
    source = (
        db.query(ScanResult)
        .filter(ScanResult.id == source_result_id, ScanResult.scan_job_id == scan_job_id)
        .first()
    )
    if not source:
        return {"error": "Source result not found"}

    vcf_id = vcf_control_id or resolve_vcf_control_for_finding(
        source.target_type, rule_id, control_id
    )
    peers: list[dict] = []
    results = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_job_id == scan_job_id,
            ScanResult.target_type == source.target_type,
        )
        .order_by(ScanResult.target_name)
        .all()
    )

    for result in results:
        if result.target_name.lower() in AGGREGATE_TARGETS:
            continue
        if result.target_type == ScanTargetType.VCENTER_APPLIANCE.value:
            continue
        if not finding_has_open_status(result, rule_id, vcf_id, control_id):
            continue
        peers.append(
            {
                "result_id": result.id,
                "target_name": result.target_name,
                "target_type": result.target_type,
                "is_current": result.id == source_result_id,
                "selected": result.id == source_result_id,
            }
        )

    return {
        "rule_id": rule_id,
        "control_id": control_id,
        "vcf_control_id": vcf_id,
        "target_type": source.target_type,
        "source_result_id": source_result_id,
        "peers": peers,
        "remediable": bool(peers)
        and source.target_type
        in {
            ScanTargetType.ESXI.value,
            ScanTargetType.VM.value,
            ScanTargetType.VCENTER_PRODUCT.value,
        },
    }


def validate_remediation_targets(
    db: Session,
    scan_job_id: int,
    source_result: ScanResult,
    target_result_ids: list[int],
    rule_id: str,
    vcf_control_id: str,
    control_id: str = "",
) -> list[ScanResult]:
    if not target_result_ids:
        raise ValueError("Select at least one target to remediate")

    rows = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_job_id == scan_job_id,
            ScanResult.id.in_(target_result_ids),
        )
        .all()
    )
    if len(rows) != len(set(target_result_ids)):
        raise ValueError("One or more selected targets were not found in this scan")

    validated: list[ScanResult] = []
    for row in rows:
        if row.target_type != source_result.target_type:
            raise ValueError(
                f"Target {row.target_name} has type {row.target_type}; "
                f"expected {source_result.target_type}"
            )
        if row.target_name.lower() in AGGREGATE_TARGETS:
            raise ValueError(f"Cannot remediate aggregate target {row.target_name}")
        if row.target_type == ScanTargetType.VCENTER_APPLIANCE.value:
            raise ValueError("VCSA appliance remediation is not supported from the web UI yet")
        if not finding_has_open_status(row, rule_id, vcf_control_id, control_id):
            raise ValueError(f"{row.target_name} does not have an open finding for {rule_id}")
        validated.append(row)
    return validated
