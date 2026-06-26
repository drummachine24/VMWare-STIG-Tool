import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session, joinedload

from app.auth.dependencies import require_admin, require_remediator, require_scanner, require_viewer
from app.config import get_settings
from app.database import get_db
from app.models import ScanJob, ScanResult, ScanStatus, VCenterConnection
from app.schemas import (
    RemediationJobResponse,
    RemediationPeersResponse,
    RemediationRequest,
    ScanJobCreate,
    ScanJobResponse,
    ScanProgressResponse,
    ScanResultResponse,
    StigPreviewRequest,
    StigPreviewResponse,
)
from app.services.finding_peers import list_remediation_peers
from app.services.remediation_jobs import create_remediation_job, get_remediation_job
from app.services.scan_progress import mark_cancelled, parse_selected_targets
from app.services.checklist_service import build_checklist_payload, ensure_result_counts
from app.services.scan_rescan import rescan_job
from app.services.stig_catalog import build_stig_preview, get_stig_scan_catalog
from app.tasks.celery_app import celery_app, run_scan_job

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("/stig-catalog")
def get_stig_catalog(_user=Depends(require_viewer)):
    return get_stig_scan_catalog()


@router.post("/stig-preview", response_model=StigPreviewResponse)
def preview_scan_stigs(payload: StigPreviewRequest, db: Session = Depends(get_db), _user=Depends(require_scanner)):
    vcenter = db.get(VCenterConnection, payload.vcenter_id)
    if not vcenter:
        raise HTTPException(status_code=404, detail="vCenter connection not found")
    selected = parse_selected_targets(payload.selected_targets_json)
    preview = build_stig_preview(
        selected,
        scan_esxi=payload.scan_esxi,
        scan_vms=payload.scan_vms,
        scan_vcenter_product=payload.scan_vcenter_product,
        scan_vcenter_appliance=payload.scan_vcenter_appliance,
        esxi_scope=payload.esxi_scope,
        esxi_cluster=payload.esxi_cluster or "",
        esxi_host=payload.esxi_host or "",
        vcenter_hostname=vcenter.hostname,
    )
    return StigPreviewResponse(**preview)


@router.get("", response_model=list[ScanJobResponse])
def list_scans(db: Session = Depends(get_db), _user=Depends(require_viewer)):
    return db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(100).all()


@router.get("/{job_id}", response_model=ScanJobResponse)
def get_scan(job_id: int, db: Session = Depends(get_db), _user=Depends(require_viewer)):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("/{job_id}/results", response_model=list[ScanResultResponse])
def get_scan_results(job_id: int, db: Session = Depends(get_db), _user=Depends(require_viewer)):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return (
        db.query(ScanResult)
        .filter(ScanResult.scan_job_id == job_id)
        .order_by(ScanResult.created_at)
        .all()
    )


@router.post("", response_model=ScanJobResponse, status_code=201)
def create_scan(payload: ScanJobCreate, db: Session = Depends(get_db), _user=Depends(require_scanner)):
    from app.services.scan_progress import parse_selected_targets

    selected = parse_selected_targets(payload.selected_targets_json)
    has_tree_targets = bool(
        selected.get("scan_vcenter_product")
        or selected.get("scan_vcenter_appliance")
        or selected.get("esxi_hosts")
        or selected.get("vms")
    )
    if not has_tree_targets and not any(
        [
            payload.scan_esxi,
            payload.scan_vms,
            payload.scan_vcenter_product,
            payload.scan_vcenter_appliance,
        ]
    ):
        raise HTTPException(status_code=400, detail="Select at least one scan target")

    job = ScanJob(**payload.model_dump())
    db.add(job)
    db.commit()
    db.refresh(job)

    task = run_scan_job.delay(job.id)
    job.celery_task_id = task.id
    job.status = ScanStatus.PENDING.value
    db.commit()
    db.refresh(job)
    return job


@router.get("/{job_id}/progress", response_model=ScanProgressResponse)
def get_scan_progress(job_id: int, db: Session = Depends(get_db), _user=Depends(require_viewer)):
    job = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.results))
        .filter(ScanJob.id == job_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanProgressResponse(
        id=job.id,
        status=job.status,
        progress_message=job.progress_message,
        progress_current=job.progress_current or 0,
        progress_total=job.progress_total or 0,
        cancel_requested=bool(job.cancel_requested),
        error_message=job.error_message,
        results=job.results,
    )


@router.post("/{job_id}/cancel")
def cancel_scan(job_id: int, db: Session = Depends(get_db), _user=Depends(require_scanner)):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status not in (ScanStatus.PENDING.value, ScanStatus.RUNNING.value):
        raise HTTPException(status_code=400, detail="Scan is not running")
    task_id = job.celery_task_id
    mark_cancelled(job_id)
    if task_id:
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    job = db.get(ScanJob, job_id)
    return {"id": job_id, "status": job.status if job else ScanStatus.CANCELLED.value}


@router.post("/{job_id}/rescan", response_model=ScanJobResponse, status_code=201)
def rescan_scan(job_id: int, db: Session = Depends(get_db), _user=Depends(require_scanner)):
    source = db.get(ScanJob, job_id)
    if not source:
        raise HTTPException(status_code=404, detail="Scan job not found")
    try:
        return rescan_job(db, source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{job_id}/results/{result_id}/checklist")
def get_result_checklist(job_id: int, result_id: int, db: Session = Depends(get_db), _user=Depends(require_viewer)):
    result = (
        db.query(ScanResult)
        .filter(ScanResult.id == result_id, ScanResult.scan_job_id == job_id)
        .first()
    )
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    try:
        result = ensure_result_counts(db, result)
        return build_checklist_payload(result)
    except Exception as exc:
        logger.exception("Checklist failed for job %s result %s", job_id, result_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/{job_id}/results/{result_id}/remediation/peers",
    response_model=RemediationPeersResponse,
)
def get_remediation_peers(
    job_id: int,
    result_id: int,
    rule_id: str,
    control_id: str = "",
    vcf_control_id: str = "",
    db: Session = Depends(get_db),
    _user=Depends(require_remediator),
):
    payload = list_remediation_peers(
        db,
        job_id,
        result_id,
        rule_id,
        control_id=control_id,
        vcf_control_id=vcf_control_id,
    )
    if payload.get("error"):
        raise HTTPException(status_code=404, detail=payload["error"])
    return RemediationPeersResponse(**payload)


@router.post(
    "/{job_id}/results/{result_id}/remediation",
    response_model=RemediationJobResponse,
    status_code=202,
)
def start_remediation(
    job_id: int,
    result_id: int,
    payload: RemediationRequest,
    db: Session = Depends(get_db),
    _user=Depends(require_remediator),
):
    try:
        job = create_remediation_job(
            db,
            job_id,
            result_id,
            payload.rule_id,
            payload.control_id,
            payload.vcf_control_id,
            payload.target_result_ids,
        )
        return job
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Remediation start failed for job %s result %s", job_id, result_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/remediation/{remediation_job_id}", response_model=RemediationJobResponse)
def get_remediation_progress(remediation_job_id: int, db: Session = Depends(get_db), _user=Depends(require_remediator)):
    job = get_remediation_job(db, remediation_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    return job


@router.get("/{job_id}/results/{result_id}/download/{file_type}")
def download_result_file(
    job_id: int,
    result_id: int,
    file_type: str,
    db: Session = Depends(get_db),
    _user=Depends(require_viewer),
):
    result = (
        db.query(ScanResult)
        .filter(ScanResult.id == result_id, ScanResult.scan_job_id == job_id)
        .first()
    )
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    path_str = result.ckl_path if file_type == "ckl" else result.json_path
    if not path_str:
        raise HTTPException(status_code=404, detail="File not available")

    path = Path(path_str)
    reports_root = Path(get_settings().reports_path).resolve()
    if not path.resolve().is_relative_to(reports_root):
        raise HTTPException(status_code=403, detail="Invalid file path")

    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    media = "application/xml" if file_type == "ckl" else "application/json"
    return FileResponse(path, media_type=media, filename=path.name)
