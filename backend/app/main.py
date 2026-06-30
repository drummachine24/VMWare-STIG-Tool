from pathlib import Path

import logging

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session, joinedload
from starlette.middleware.sessions import SessionMiddleware

from app.api import auth_routes
from app.api import remediation as remediation_api
from app.api import schedules as schedules_api
from app.api import scans as scans_api
from app.api import vcenters as vcenters_api
from app.auth.dependencies import require_admin, require_scanner, require_viewer
from app.auth.middleware import AuthMiddleware
from app.auth.root_path import RootPathStripMiddleware
from app.config import get_settings
from app.database import get_db, init_db
from app.models import ScanJob, ScanResult, ScanSchedule, VCenterConnection
from app.services.app_secret import ensure_app_secret_key, resolve_app_secret_key
from app.services.credential_key import sync_credential_key_file_from_env
from app.services.crypto import encrypt_secret
from app.services.dashboard_metrics import get_dashboard_metrics, metrics_as_dict
from app.services.preflight import run_preflight
from app.services.scan_rescan import rescan_job
from app.tasks.celery_app import run_scan_job
from app.web import render, url_for_path

try:
    ensure_app_secret_key()
    sync_credential_key_file_from_env()
except Exception as exc:
    import logging

    logging.getLogger(__name__).warning("App secret auto-generation skipped: %s", exc)

settings = get_settings()
_app_secret_key, _app_secret_source = resolve_app_secret_key(settings)
app = FastAPI(
    title="VMware STIG Scan Tool",
    version="0.2.0",
    root_path=settings.app_root_path or "",
)

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
_static_logger = logging.getLogger(__name__)


@app.get("/static/{asset_path:path}", include_in_schema=False)
async def serve_static(asset_path: str):
    """Serve JS assets explicitly (StaticFiles mount can 404 on SELinux bind mounts)."""
    if not asset_path or asset_path.endswith("/") or ".." in asset_path.split("/"):
        raise HTTPException(status_code=404, detail="Not found")
    candidate = (static_dir / asset_path).resolve()
    try:
        candidate.relative_to(static_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None
    if not candidate.is_file():
        _static_logger.warning("Static asset missing or unreadable: %s", candidate)
        raise HTTPException(status_code=404, detail="Not found")
    media_type = None
    if candidate.suffix == ".js":
        media_type = "application/javascript"
    elif candidate.suffix == ".css":
        media_type = "text/css"
    elif candidate.suffix == ".png":
        media_type = "image/png"
    headers = {"Cache-Control": "no-cache, must-revalidate"}
    return FileResponse(candidate, media_type=media_type, headers=headers)

app.add_middleware(AuthMiddleware)
app.add_middleware(RootPathStripMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=_app_secret_key,
    https_only=(settings.app_public_url or "").startswith("https://"),
)

app.include_router(auth_routes.router)
app.include_router(vcenters_api.router)
app.include_router(scans_api.router)
app.include_router(remediation_api.router)
app.include_router(schedules_api.router)


@app.on_event("startup")
def on_startup():
    init_db()


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url_for_path(path), status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_viewer),
):
    recent_jobs = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.vcenter))
        .order_by(ScanJob.created_at.desc())
        .limit(10)
        .all()
    )
    vcenters = db.query(VCenterConnection).count()
    schedules = db.query(ScanSchedule).filter(ScanSchedule.enabled.is_(True)).count()
    metrics = get_dashboard_metrics(db)
    return render(
        request,
        "dashboard.html",
        {
            "recent_jobs": recent_jobs,
            "vcenter_count": vcenters,
            "schedule_count": schedules,
            "metrics": metrics,
            "metrics_json": metrics_as_dict(metrics),
        },
    )


@app.get("/vcenters", response_class=HTMLResponse)
def vcenters_page(
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    vcenters = db.query(VCenterConnection).order_by(VCenterConnection.name).all()
    return render(request, "vcenters.html", {"vcenters": vcenters})


@app.post("/vcenters")
def create_vcenter_form(
    name: str = Form(...),
    hostname: str = Form(...),
    api_username: str = Form(...),
    api_password: str = Form(...),
    ssh_username: str = Form("root"),
    ssh_password: str = Form(""),
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    record = VCenterConnection(
        name=name,
        hostname=hostname,
        api_username=api_username,
        api_password_encrypted=encrypt_secret(api_password),
        ssh_username=ssh_username or "root",
        ssh_password_encrypted=encrypt_secret(ssh_password) if ssh_password else None,
    )
    db.add(record)
    db.commit()
    return _redirect("/vcenters")


@app.get("/vcenters/{vcenter_id}/preflight", response_class=HTMLResponse)
def preflight_page(
    vcenter_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_scanner),
):
    vcenter = db.get(VCenterConnection, vcenter_id)
    if not vcenter:
        return _redirect("/vcenters")
    checks = run_preflight(vcenter, check_ssh=True)
    return render(request, "preflight.html", {"vcenter": vcenter, "checks": checks})


@app.get("/scans", response_class=HTMLResponse)
def scans_page(
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_viewer),
):
    jobs = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.vcenter))
        .order_by(ScanJob.created_at.desc())
        .limit(50)
        .all()
    )
    vcenters = db.query(VCenterConnection).order_by(VCenterConnection.name).all()
    return render(request, "scans.html", {"jobs": jobs, "vcenters": vcenters})


@app.get("/scans/new", response_class=HTMLResponse)
def new_scan_page(
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_scanner),
):
    vcenters = db.query(VCenterConnection).order_by(VCenterConnection.name).all()
    return render(request, "scan_new.html", {"vcenters": vcenters})


@app.post("/scans")
def create_scan_form(
    name: str = Form(...),
    vcenter_id: int = Form(...),
    scan_esxi: bool = Form(False),
    scan_vms: bool = Form(False),
    scan_vcenter_product: bool = Form(False),
    scan_vcenter_appliance: bool = Form(False),
    esxi_scope: str = Form("all_hosts"),
    esxi_cluster: str = Form(""),
    esxi_host: str = Form(""),
    vm_scope: str = Form("all"),
    selected_targets_json: str = Form(""),
    db: Session = Depends(get_db),
    _user=Depends(require_scanner),
):
    job = ScanJob(
        name=name,
        vcenter_id=vcenter_id,
        scan_esxi=scan_esxi,
        scan_vms=scan_vms,
        scan_vcenter_product=scan_vcenter_product,
        scan_vcenter_appliance=scan_vcenter_appliance,
        esxi_scope=esxi_scope,
        esxi_cluster=esxi_cluster or None,
        esxi_host=esxi_host or None,
        vm_scope=vm_scope,
        selected_targets_json=selected_targets_json or None,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    task = run_scan_job.delay(job.id)
    job.celery_task_id = task.id
    db.commit()
    return _redirect(f"/scans/{job.id}")


@app.post("/scans/{job_id}/rescan")
def rescan_scan_form(
    job_id: int,
    db: Session = Depends(get_db),
    _user=Depends(require_scanner),
):
    source = db.get(ScanJob, job_id)
    if not source:
        return _redirect("/scans")
    try:
        job = rescan_job(db, source)
    except ValueError:
        return _redirect(f"/scans/{job_id}")
    return _redirect(f"/scans/{job.id}")


@app.get("/scans/{job_id}", response_class=HTMLResponse)
def scan_detail(
    job_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_viewer),
):
    job = (
        db.query(ScanJob)
        .options(joinedload(ScanJob.vcenter), joinedload(ScanJob.results))
        .filter(ScanJob.id == job_id)
        .first()
    )
    if not job:
        return _redirect("/scans")
    return render(request, "scan_detail.html", {"job": job})


@app.get("/scans/{job_id}/results/{result_id}", response_class=HTMLResponse)
def result_checklist_page(
    job_id: int,
    result_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_viewer),
):
    job = db.get(ScanJob, job_id)
    result = (
        db.query(ScanResult)
        .filter(ScanResult.id == result_id, ScanResult.scan_job_id == job_id)
        .first()
    )
    if not job or not result:
        return _redirect("/scans")
    return render(request, "result_checklist.html", {"job": job, "result": result})


@app.get("/schedules", response_class=HTMLResponse)
def schedules_page(
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    schedules = (
        db.query(ScanSchedule)
        .options(joinedload(ScanSchedule.vcenter))
        .order_by(ScanSchedule.name)
        .all()
    )
    vcenters = db.query(VCenterConnection).order_by(VCenterConnection.name).all()
    return render(request, "schedules.html", {"schedules": schedules, "vcenters": vcenters})


@app.post("/schedules")
def create_schedule_form(
    name: str = Form(...),
    vcenter_id: int = Form(...),
    cron_expression: str = Form("0 2 * * 0"),
    scan_esxi: bool = Form(False),
    scan_vms: bool = Form(False),
    scan_vcenter_product: bool = Form(False),
    scan_vcenter_appliance: bool = Form(False),
    esxi_scope: str = Form("all_hosts"),
    ckl_export_path: str = Form(""),
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    from app.services.ckl_export import normalize_ckl_export_path

    try:
        export_path = normalize_ckl_export_path(ckl_export_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record = ScanSchedule(
        name=name,
        vcenter_id=vcenter_id,
        cron_expression=cron_expression,
        scan_esxi=scan_esxi,
        scan_vms=scan_vms,
        scan_vcenter_product=scan_vcenter_product,
        scan_vcenter_appliance=scan_vcenter_appliance,
        esxi_scope=esxi_scope,
        ckl_export_path=export_path or None,
    )
    db.add(record)
    db.commit()
    return _redirect("/schedules")


@app.get("/health")
def health():
    sample = static_dir / "app.js"
    readable = False
    if sample.is_file():
        try:
            with sample.open("rb") as handle:
                readable = bool(handle.read(1))
        except OSError:
            readable = False
    return {
        "status": "ok",
        "static_dir": str(static_dir),
        "static_app_js": sample.is_file(),
        "static_app_js_readable": readable,
    }
