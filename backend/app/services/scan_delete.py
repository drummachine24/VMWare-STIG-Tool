import shutil
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.models import RemediationJob, RemediationTarget, ScanJob, ScanStatus

DELETABLE_STATUSES = frozenset(
    {
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }
)


def _safe_unlink(path_str: str | None, reports_root: Path) -> None:
    if not path_str:
        return
    path = Path(path_str).resolve()
    if path.is_relative_to(reports_root) and path.is_file():
        path.unlink()


def _safe_rmtree(path_str: str | None, reports_root: Path) -> None:
    if not path_str:
        return
    path = Path(path_str).resolve()
    if path.is_relative_to(reports_root) and path.is_dir():
        shutil.rmtree(path)


def _purge_scan_job(db: Session, job: ScanJob, reports_root: Path) -> None:
    result_ids = [r.id for r in job.results]
    if result_ids:
        db.query(RemediationTarget).filter(
            RemediationTarget.scan_result_id.in_(result_ids)
        ).delete(synchronize_session=False)

    for rem_job in (
        db.query(RemediationJob).filter(RemediationJob.scan_job_id == job.id).all()
    ):
        db.delete(rem_job)

    for result in job.results:
        _safe_unlink(result.json_path, reports_root)
        _safe_unlink(result.ckl_path, reports_root)

    _safe_unlink(str(reports_root / f"inputs-job-{job.id}.yml"), reports_root)
    _safe_unlink(job.ckl_export_path, reports_root)
    _safe_rmtree(job.ckl_export_dir, reports_root)

    db.delete(job)


def delete_scan_job(db: Session, job: ScanJob) -> None:
    if job.status not in DELETABLE_STATUSES:
        raise ValueError("Only completed, failed, or cancelled scans can be deleted")

    reports_root = Path(get_settings().reports_path).resolve()
    loaded = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.results))
        .filter(ScanJob.id == job.id)
        .first()
    )
    if not loaded:
        return
    _purge_scan_job(db, loaded, reports_root)
    db.commit()


def delete_all_deletable_scan_jobs(db: Session) -> dict[str, int]:
    reports_root = Path(get_settings().reports_path).resolve()
    jobs = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.results))
        .filter(ScanJob.status.in_(DELETABLE_STATUSES))
        .all()
    )
    skipped = (
        db.query(func.count(ScanJob.id))
        .filter(~ScanJob.status.in_(DELETABLE_STATUSES))
        .scalar()
        or 0
    )
    for job in jobs:
        _purge_scan_job(db, job, reports_root)
    db.commit()
    return {"deleted": len(jobs), "skipped": skipped}


def count_deletable_scan_jobs(db: Session) -> int:
    return (
        db.query(func.count(ScanJob.id))
        .filter(ScanJob.status.in_(DELETABLE_STATUSES))
        .scalar()
        or 0
    )