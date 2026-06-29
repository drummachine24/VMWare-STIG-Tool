import logging
from datetime import datetime, timezone

from celery import Celery
from croniter import croniter
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.database import SessionLocal
from app.models import RemediationJob, ScanJob, ScanResult, ScanSchedule, ScanStatus
from app.services.scan_engine import ScanEngine
from app.services.scan_progress import is_cancelled, save_result, update_progress

logger = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery("stigtool", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(name="app.tasks.check_worker_toolchain")
def check_worker_toolchain() -> dict:
    """Verify scan tools inside the worker container."""
    import shutil
    import subprocess

    cinc = shutil.which("cinc-auditor")
    saf = shutil.which("saf")
    pwsh = shutil.which("pwsh")

    cinc_version = ""
    if cinc:
        try:
            result = subprocess.run(
                ["cinc-auditor", "version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            cinc_version = (result.stdout or result.stderr).strip().splitlines()[0]
        except Exception:
            cinc_version = cinc

    saf_version = ""
    if saf:
        try:
            result = subprocess.run(
                ["saf", "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            saf_version = (result.stdout or result.stderr).strip().splitlines()[0]
        except Exception:
            saf_version = saf

    train_vmware = False
    train_msg = "train-vmware plugin not installed"
    if cinc:
        try:
            result = subprocess.run(
                ["cinc-auditor", "plugin", "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if "train-vmware" in result.stdout:
                train_vmware = True
                for line in result.stdout.splitlines():
                    if "train-vmware" in line:
                        train_msg = f"Installed: {line.strip()}"
                        break
            else:
                train_msg = "Not installed — run: bash scripts/install-train-vmware.sh"
        except Exception as exc:
            train_msg = f"Could not list plugins: {exc}"

    powercli = False
    powercli_msg = "PowerShell (pwsh) not found on scan worker"
    if pwsh:
        try:
            result = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    "Import-Module VMware.VimAutomation.Core -ErrorAction Stop; "
                    "(Get-Module VMware.VimAutomation.Core).Version.ToString()",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            version = (result.stdout or "").strip()
            if result.returncode == 0 and version:
                powercli = True
                powercli_msg = f"VMware.VimAutomation.Core {version}"
            else:
                detail = (result.stderr or result.stdout or "module not found").strip()
                powercli_msg = (
                    "PowerCLI not installed — run: bash scripts/fix-powercli.sh "
                    f"({detail[:160]})"
                )
        except Exception as exc:
            powercli_msg = f"PowerCLI check failed: {exc}"

    return {
        "cinc_auditor": cinc is not None,
        "cinc_auditor_message": cinc_version or "Not found on scan worker",
        "saf_cli": saf is not None,
        "saf_cli_message": saf_version or "Not found on scan worker",
        "pwsh": pwsh is not None,
        "powercli": powercli,
        "powercli_message": powercli_msg,
        "train_vmware": train_vmware,
        "train_vmware_message": train_msg,
    }


@celery_app.task(name="app.tasks.fetch_vcenter_inventory")
def fetch_vcenter_inventory(vcenter_id: int) -> dict:
    from app.models import VCenterConnection
    from app.services.vcenter_inventory import fetch_inventory

    db: Session = SessionLocal()
    try:
        vcenter = db.get(VCenterConnection, vcenter_id)
        if not vcenter:
            return {"error": "vCenter connection not found"}
        return fetch_inventory(vcenter)
    except Exception as exc:
        logger.exception("Inventory fetch failed for vcenter %s", vcenter_id)
        return {"error": str(exc)}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.run_scan_job")
def run_scan_job(self, job_id: int) -> dict:
    db: Session = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return {"error": f"Job {job_id} not found"}

        job.status = ScanStatus.RUNNING.value
        job.celery_task_id = self.request.id
        job.started_at = datetime.now(timezone.utc)
        job.error_message = None
        job.cancel_requested = False
        job.progress_current = 0
        job.progress_total = 0
        job.progress_message = "Starting scan..."
        db.commit()

        vcenter = job.vcenter
        engine = ScanEngine()

        def on_result(result):
            save_result(job_id, result)

        execution = engine.execute_scan(
            job, vcenter, job_id=job_id, on_result=on_result
        )

        job = db.get(ScanJob, job_id)
        if not job:
            return {"error": "Job disappeared"}

        if is_cancelled(job_id) or execution.error == "Scan cancelled by user":
            job.status = ScanStatus.CANCELLED.value
            job.error_message = execution.error or "Scan cancelled by user"
            job.progress_message = "Scan cancelled by user"
        elif execution.error:
            job.status = ScanStatus.FAILED.value
            job.error_message = execution.error
        elif any(r.status == ScanStatus.FAILED.value for r in execution.results):
            job.status = ScanStatus.FAILED.value
            job.error_message = "One or more scan targets failed"
        else:
            job.status = ScanStatus.COMPLETED.value
            job.error_message = None

        if job.status == ScanStatus.COMPLETED.value and job.ckl_export_path:
            from app.services.ckl_export import export_job_ckls

            results = (
                db.query(ScanResult).filter(ScanResult.scan_job_id == job_id).all()
            )
            export_result = export_job_ckls(job, results)
            if export_result.get("export_dir") and export_result.get("count"):
                job.ckl_export_dir = export_result["export_dir"]
                job.progress_message = (
                    f"Scan complete — exported {export_result['count']} CKL file(s) to "
                    f"{export_result['export_dir']}"
                )
            elif export_result.get("error"):
                job.progress_message = (
                    f"Scan complete — CKL export failed: {export_result['error']}"
                )
                logger.warning(
                    "CKL export failed for job %s: %s", job_id, export_result["error"]
                )

        job.completed_at = datetime.now(timezone.utc)
        update_progress(
            job_id,
            message=job.progress_message or "Done",
            current=job.progress_current,
            total=job.progress_total,
        )
        db.commit()
        return {"job_id": job_id, "status": job.status, "results": len(execution.results)}
    except Exception as exc:
        logger.exception("Task failed for job %s", job_id)
        if job := db.get(ScanJob, job_id):
            job.status = ScanStatus.FAILED.value
            job.error_message = str(exc)
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
        return {"error": str(exc)}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.run_remediation_job")
def run_remediation_job(self, remediation_job_id: int) -> dict:
    from app.models import RemediationStatus, RemediationTarget, ScanJob
    from app.services.remediation_engine import RemediationEngine
    from app.services.remediation_jobs import finalize_remediation_job, update_remediation_progress

    db: Session = SessionLocal()
    try:
        job = (
            db.query(RemediationJob)
            .options(joinedload(RemediationJob.targets))
            .filter(RemediationJob.id == remediation_job_id)
            .first()
        )
        if not job:
            return {"error": f"Remediation job {remediation_job_id} not found"}

        scan_job = db.get(ScanJob, job.scan_job_id)
        if not scan_job:
            job.status = RemediationStatus.FAILED.value
            job.error_message = "Scan job not found"
            db.commit()
            return {"error": job.error_message}

        vcenter = scan_job.vcenter
        engine = RemediationEngine()
        job.status = RemediationStatus.RUNNING.value
        job.celery_task_id = self.request.id
        job.progress_current = 0
        job.progress_message = "Starting remediation..."
        db.commit()

        completed = 0
        for index, target in enumerate(job.targets, start=1):
            update_remediation_progress(
                db,
                remediation_job_id,
                message=f"Remediating {target.target_name} ({index}/{len(job.targets)})...",
                current=index - 1,
            )
            target.status = RemediationStatus.RUNNING.value
            db.commit()

            try:
                result = engine.run_control(
                    vcenter,
                    job.target_type,
                    target.target_name,
                    job.vcf_control_id,
                    remediation_job_id,
                    scan_inputs_yaml=scan_job.inputs_yaml,
                    variables_override=job.variables_content,
                )
                target.status = result["status"]
                target.message = result.get("message")
                target.log_path = result.get("log_path")
                target.completed_at = datetime.now(timezone.utc)
                if result["status"] == RemediationStatus.COMPLETED.value:
                    completed += 1
            except Exception as exc:
                logger.exception(
                    "Remediation failed for target %s job %s",
                    target.target_name,
                    remediation_job_id,
                )
                target.status = RemediationStatus.FAILED.value
                target.message = str(exc)
                target.completed_at = datetime.now(timezone.utc)

            db.commit()
            update_remediation_progress(
                db,
                remediation_job_id,
                current=index,
                message=f"Finished {target.target_name}",
            )

        finalize_remediation_job(db, remediation_job_id)
        job = db.get(RemediationJob, remediation_job_id)
        return {
            "remediation_job_id": remediation_job_id,
            "status": job.status if job else RemediationStatus.FAILED.value,
            "completed_targets": completed,
            "total_targets": len(job.targets) if job else 0,
        }
    except Exception as exc:
        logger.exception("Remediation task failed for job %s", remediation_job_id)
        if job := db.get(RemediationJob, remediation_job_id):
            job.status = RemediationStatus.FAILED.value
            job.error_message = str(exc)
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
        return {"error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="app.tasks.check_schedules")
def check_schedules() -> dict:
    """Poll enabled schedules and enqueue scan jobs when due."""
    db: Session = SessionLocal()
    triggered = []
    now = datetime.now(timezone.utc)
    try:
        schedules = db.query(ScanSchedule).filter(ScanSchedule.enabled.is_(True)).all()
        for schedule in schedules:
            cron = croniter(schedule.cron_expression, now)
            prev_run = cron.get_prev(datetime)
            if schedule.last_run_at and schedule.last_run_at.replace(
                tzinfo=timezone.utc
            ) >= prev_run.replace(tzinfo=timezone.utc):
                continue

            job = ScanJob(
                name=f"{schedule.name} @ {now.isoformat()}",
                vcenter_id=schedule.vcenter_id,
                schedule_id=schedule.id,
                ckl_export_path=schedule.ckl_export_path,
                scan_esxi=schedule.scan_esxi,
                scan_vms=schedule.scan_vms,
                scan_vcenter_product=schedule.scan_vcenter_product,
                scan_vcenter_appliance=schedule.scan_vcenter_appliance,
                esxi_scope=schedule.esxi_scope,
                esxi_cluster=schedule.esxi_cluster,
                esxi_host=schedule.esxi_host,
                vm_scope=schedule.vm_scope,
                inputs_yaml=schedule.inputs_yaml,
            )
            db.add(job)
            db.flush()
            run_scan_job.delay(job.id)
            schedule.last_run_at = now
            triggered.append(schedule.name)
        db.commit()
        return {"triggered": triggered}
    finally:
        db.close()


celery_app.conf.beat_schedule = {
    "check-scan-schedules": {
        "task": "app.tasks.check_schedules",
        "schedule": 60.0,
    },
}
