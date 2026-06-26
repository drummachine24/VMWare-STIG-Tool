import json

from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import ScanJob, ScanResult, ScanStatus


def get_job(job_id: int, db: Session | None = None) -> ScanJob | None:
    own = db is None
    if own:
        db = SessionLocal()
    try:
        return db.get(ScanJob, job_id)
    finally:
        if own:
            db.close()


def is_cancelled(job_id: int) -> bool:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return True
        return job.status == ScanStatus.CANCELLED.value or bool(job.cancel_requested)
    finally:
        db.close()


def update_progress(
    job_id: int,
    *,
    message: str,
    current: int | None = None,
    total: int | None = None,
) -> None:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return
        job.progress_message = message
        if current is not None:
            job.progress_current = current
        if total is not None:
            job.progress_total = total
        db.commit()
    finally:
        db.close()


def save_result(job_id: int, result) -> None:
    """Persist a single scan result while the job is still running."""
    db = SessionLocal()
    try:
        db.add(
            ScanResult(
                scan_job_id=job_id,
                target_type=result.target_type,
                target_name=result.target_name,
                status=result.status,
                json_path=result.json_path,
                ckl_path=result.ckl_path,
                passed=result.passed,
                failed=result.failed,
                skipped=result.skipped,
                count_nf=result.count_nf,
                count_nr=result.count_nr,
                count_na=result.count_na,
                count_open=result.count_open,
                summary=result.summary,
            )
        )
        db.commit()
    finally:
        db.close()


def mark_cancelled(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if job:
            job.cancel_requested = True
            job.progress_message = "Cancellation requested — stopping after current step..."
            if job.status == ScanStatus.RUNNING.value:
                job.status = ScanStatus.CANCELLED.value
            db.commit()
    finally:
        db.close()


def parse_selected_targets(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}
