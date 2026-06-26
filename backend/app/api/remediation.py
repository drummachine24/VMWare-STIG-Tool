from fastapi import APIRouter, Depends

from app.auth.dependencies import require_viewer
from app.services.remediation_catalog import RemediationCatalog

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


@router.get("/catalog")
def get_remediation_catalog(_user=Depends(require_viewer)):
    return RemediationCatalog().list_assets()


@router.get("/status")
def get_remediation_status(_user=Depends(require_viewer)):
    return RemediationCatalog().sync_status()
