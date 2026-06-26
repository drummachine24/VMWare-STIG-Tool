from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import require_admin
from app.database import get_db
from app.models import ScanSchedule
from app.schemas import ScheduleCreate, ScheduleResponse
from app.services.ckl_export import normalize_ckl_export_path

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


@router.get("", response_model=list[ScheduleResponse])
def list_schedules(db: Session = Depends(get_db), _user=Depends(require_admin)):
    return db.query(ScanSchedule).order_by(ScanSchedule.name).all()


@router.post("", response_model=ScheduleResponse, status_code=201)
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db), _user=Depends(require_admin)):
    if db.query(ScanSchedule).filter(ScanSchedule.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Schedule name already exists")

    try:
        export_path = normalize_ckl_export_path(payload.ckl_export_path or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    data = payload.model_dump()
    data["ckl_export_path"] = export_path or None
    record = ScanSchedule(**data)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.patch("/{schedule_id}/toggle", response_model=ScheduleResponse)
def toggle_schedule(schedule_id: int, db: Session = Depends(get_db), _user=Depends(require_admin)):
    record = db.get(ScanSchedule, schedule_id)
    if not record:
        raise HTTPException(status_code=404, detail="Schedule not found")
    record.enabled = not record.enabled
    db.commit()
    db.refresh(record)
    return record


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), _user=Depends(require_admin)):
    record = db.get(ScanSchedule, schedule_id)
    if not record:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(record)
    db.commit()
