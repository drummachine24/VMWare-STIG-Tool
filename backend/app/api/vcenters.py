from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import require_admin, require_scanner, require_viewer
from app.database import get_db
from app.models import VCenterConnection
from app.schemas import PreflightResponse, VCenterCreate, VCenterCredentialsUpdate, VCenterResponse
from app.services.crypto import encrypt_secret
from app.services.preflight import run_preflight
from app.tasks.celery_app import fetch_vcenter_inventory

router = APIRouter(prefix="/api/vcenters", tags=["vcenters"])


@router.get("", response_model=list[VCenterResponse])
def list_vcenters(db: Session = Depends(get_db), _user=Depends(require_scanner)):
    return db.query(VCenterConnection).order_by(VCenterConnection.name).all()


@router.post("", response_model=VCenterResponse, status_code=201)
def create_vcenter(payload: VCenterCreate, db: Session = Depends(get_db), _user=Depends(require_admin)):
    if db.query(VCenterConnection).filter(VCenterConnection.name == payload.name).first():
        raise HTTPException(status_code=400, detail="vCenter connection name already exists")

    record = VCenterConnection(
        name=payload.name,
        hostname=payload.hostname,
        api_username=payload.api_username,
        api_password_encrypted=encrypt_secret(payload.api_password),
        ssh_username=payload.ssh_username,
        ssh_password_encrypted=(
            encrypt_secret(payload.ssh_password) if payload.ssh_password else None
        ),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.delete("/{vcenter_id}", status_code=204)
def delete_vcenter(vcenter_id: int, db: Session = Depends(get_db), _user=Depends(require_admin)):
    record = db.get(VCenterConnection, vcenter_id)
    if not record:
        raise HTTPException(status_code=404, detail="vCenter connection not found")
    db.delete(record)
    db.commit()


@router.patch("/{vcenter_id}/credentials", response_model=VCenterResponse)
def update_vcenter_credentials(
    vcenter_id: int,
    payload: VCenterCredentialsUpdate,
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    record = db.get(VCenterConnection, vcenter_id)
    if not record:
        raise HTTPException(status_code=404, detail="vCenter connection not found")
    if payload.api_username is not None:
        record.api_username = payload.api_username
    if payload.api_password is not None:
        record.api_password_encrypted = encrypt_secret(payload.api_password)
    if payload.ssh_username is not None:
        record.ssh_username = payload.ssh_username or "root"
    if payload.ssh_password is not None:
        record.ssh_password_encrypted = (
            encrypt_secret(payload.ssh_password) if payload.ssh_password else None
        )
    db.commit()
    db.refresh(record)
    return record


@router.post("/{vcenter_id}/preflight", response_model=PreflightResponse)
def preflight_vcenter(
    vcenter_id: int,
    check_ssh: bool = False,
    db: Session = Depends(get_db),
    _user=Depends(require_scanner),
):
    record = db.get(VCenterConnection, vcenter_id)
    if not record:
        raise HTTPException(status_code=404, detail="vCenter connection not found")
    return run_preflight(record, check_ssh=check_ssh)


@router.get("/{vcenter_id}/inventory")
def get_vcenter_inventory(
    vcenter_id: int,
    db: Session = Depends(get_db),
    _user=Depends(require_scanner),
):
    record = db.get(VCenterConnection, vcenter_id)
    if not record:
        raise HTTPException(status_code=404, detail="vCenter connection not found")
    try:
        result = fetch_vcenter_inventory.apply_async(args=[vcenter_id]).get(timeout=300)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if isinstance(result, dict) and result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])
    return result
