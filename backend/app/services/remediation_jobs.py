import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session, joinedload

from app.models import RemediationJob, RemediationStatus, RemediationTarget, ScanResult
from app.services.finding_peers import (
    resolve_vcf_control_for_finding,
    validate_remediation_targets,
)
from app.services.remediation_engine import RemediationEngine

logger = logging.getLogger(__name__)


def create_remediation_job(
    db: Session,
    scan_job_id: int,
    source_result_id: int,
    rule_id: str,
    control_id: str,
    vcf_control_id: str,
    target_result_ids: list[int],
    variables_content: str | None = None,
) -> RemediationJob:
    source = (
        db.query(ScanResult)
        .filter(ScanResult.id == source_result_id, ScanResult.scan_job_id == scan_job_id)
        .first()
    )
    if not source:
        raise ValueError("Source result not found")

    vcf_id = vcf_control_id or resolve_vcf_control_for_finding(
        source.target_type, rule_id, control_id
    )
    if not vcf_id:
        raise ValueError("Could not resolve VCF control id for this finding")

    targets = validate_remediation_targets(
        db,
        scan_job_id,
        source,
        target_result_ids,
        rule_id,
        vcf_id,
        control_id,
    )

    if variables_content:
        RemediationEngine().generate_variables_content(
            target_type=source.target_type,
            vcf_control_id=vcf_id,
            custom_content=variables_content,
        )

    job = RemediationJob(
        scan_job_id=scan_job_id,
        source_result_id=source_result_id,
        rule_id=rule_id,
        control_id=control_id,
        vcf_control_id=vcf_id,
        target_type=source.target_type,
        status=RemediationStatus.PENDING.value,
        progress_total=len(targets),
        progress_message="Queued for remediation...",
        variables_content=variables_content,
    )
    db.add(job)
    db.flush()

    for target in targets:
        db.add(
            RemediationTarget(
                remediation_job_id=job.id,
                scan_result_id=target.id,
                target_name=target.target_name,
                status=RemediationStatus.PENDING.value,
            )
        )

    db.commit()
    db.refresh(job)

    from app.tasks.celery_app import run_remediation_job

    task = run_remediation_job.delay(job.id)
    job.celery_task_id = task.id
    db.commit()
    db.refresh(job)
    return job


def get_remediation_job(db: Session, remediation_job_id: int) -> RemediationJob | None:
    return (
        db.query(RemediationJob)
        .options(joinedload(RemediationJob.targets))
        .filter(RemediationJob.id == remediation_job_id)
        .first()
    )


def update_remediation_progress(
    db: Session,
    remediation_job_id: int,
    *,
    message: str | None = None,
    current: int | None = None,
    total: int | None = None,
    status: str | None = None,
    error_message: str | None = None,
) -> None:
    job = db.get(RemediationJob, remediation_job_id)
    if not job:
        return
    if message is not None:
        job.progress_message = message
    if current is not None:
        job.progress_current = current
    if total is not None:
        job.progress_total = total
    if status is not None:
        job.status = status
    if error_message is not None:
        job.error_message = error_message
    db.commit()


def finalize_remediation_job(db: Session, remediation_job_id: int) -> None:
    job = (
        db.query(RemediationJob)
        .options(joinedload(RemediationJob.targets))
        .filter(RemediationJob.id == remediation_job_id)
        .first()
    )
    if not job:
        return

    statuses = {t.status for t in job.targets}
    if RemediationStatus.FAILED.value in statuses and len(statuses) > 1:
        job.status = RemediationStatus.PARTIAL.value
    elif RemediationStatus.FAILED.value in statuses:
        job.status = RemediationStatus.FAILED.value
    else:
        job.status = RemediationStatus.COMPLETED.value
    job.completed_at = datetime.now(timezone.utc)
    db.commit()
