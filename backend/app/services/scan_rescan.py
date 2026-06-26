from sqlalchemy.orm import Session

from app.models import ScanJob, ScanStatus
from app.tasks.celery_app import run_scan_job

RESCANNABLE_STATUSES = frozenset(
    {
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }
)


def rescan_job(db: Session, source: ScanJob) -> ScanJob:
    if source.status not in RESCANNABLE_STATUSES:
        raise ValueError("Only completed, failed, or cancelled scans can be rescanned")

    job = ScanJob(
        name=f"{source.name} (rescan)",
        vcenter_id=source.vcenter_id,
        scan_esxi=source.scan_esxi,
        scan_vms=source.scan_vms,
        scan_vcenter_product=source.scan_vcenter_product,
        scan_vcenter_appliance=source.scan_vcenter_appliance,
        esxi_scope=source.esxi_scope,
        esxi_cluster=source.esxi_cluster,
        esxi_host=source.esxi_host,
        vm_scope=source.vm_scope,
        inputs_yaml=source.inputs_yaml,
        selected_targets_json=source.selected_targets_json,
        status=ScanStatus.PENDING.value,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    task = run_scan_job.delay(job.id)
    job.celery_task_id = task.id
    db.commit()
    db.refresh(job)
    return job
