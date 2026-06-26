import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import ScanResult
from app.services.remediation_catalog import RemediationCatalog
from app.services.remediation_index import RemediationIndex
from app.services.result_parser import parse_scan_artifact

logger = logging.getLogger(__name__)


def ensure_result_counts(db: Session, result: ScanResult) -> ScanResult:
    json_path = Path(result.json_path) if result.json_path else None
    ckl_path = Path(result.ckl_path) if result.ckl_path else None
    if not json_path and not ckl_path:
        return result

    parsed = parse_scan_artifact(json_path, ckl_path)
    c = parsed.counts
    if not any([c.nf, c.nr, c.na, c.open]):
        return result

    result.count_nf = c.nf
    result.count_nr = c.nr
    result.count_na = c.na
    result.count_open = c.open
    if parsed.summary:
        result.summary = parsed.summary
    db.commit()
    db.refresh(result)
    return result


def build_checklist_payload(result: ScanResult) -> dict:
    json_path = Path(result.json_path) if result.json_path else None
    ckl_path = Path(result.ckl_path) if result.ckl_path else None
    parsed = parse_scan_artifact(json_path, ckl_path)

    index = RemediationIndex()
    try:
        items = index.enrich_checklist(result.target_type, parsed.items)
    except Exception as exc:
        logger.exception("Remediation enrichment failed for result %s", result.id)
        items = [item.__dict__ for item in parsed.items]
        for item in items:
            item.setdefault("remediation_script", "")
            item.setdefault("remediation_source", "")
            item["remediation_error"] = str(exc)

    counts = parsed.counts.as_dict()

    catalog = RemediationCatalog()
    return {
        "result_id": result.id,
        "scan_job_id": result.scan_job_id,
        "target_name": result.target_name,
        "target_type": result.target_type,
        "status": result.status,
        "counts": counts,
        "items": items,
        "has_ckl": bool(result.ckl_path and ckl_path and ckl_path.exists()),
        "has_json": bool(result.json_path and json_path and json_path.exists()),
        "remediation_status": catalog.sync_status(),
    }
