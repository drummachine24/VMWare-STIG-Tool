import logging
import socket

from app.config import get_settings
from app.models import VCenterConnection
from app.schemas import PreflightResponse

logger = logging.getLogger(__name__)


def check_tcp(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"Port {port} reachable on {host}"
    except OSError as exc:
        return False, f"Port {port} not reachable on {host}: {exc}"


def _check_worker_toolchain(settings) -> dict:
    if settings.dry_run:
        return {
            "cinc_auditor": True,
            "cinc_auditor_message": "Dry-run mode (skipped worker check)",
            "saf_cli": True,
            "saf_cli_message": "Dry-run mode (skipped worker check)",
            "worker_reachable": True,
            "powercli": True,
            "powercli_message": "Dry-run mode (skipped worker check)",
            "train_vmware": True,
            "train_vmware_message": "Dry-run mode",
        }

    try:
        from app.tasks.celery_app import check_worker_toolchain

        result = check_worker_toolchain.apply_async().get(timeout=30)
        result["worker_reachable"] = True
        return result
    except Exception as exc:
        logger.warning("Worker toolchain check failed: %s", exc)
        return {
            "cinc_auditor": False,
            "cinc_auditor_message": f"Scan worker unreachable: {exc}",
            "saf_cli": False,
            "saf_cli_message": f"Scan worker unreachable: {exc}",
            "worker_reachable": False,
            "powercli": False,
            "powercli_message": "Worker not responding",
            "train_vmware": False,
            "train_vmware_message": "Worker not responding",
        }


def run_preflight(vcenter: VCenterConnection, check_ssh: bool = False) -> PreflightResponse:
    settings = get_settings()
    api_ok, api_msg = check_tcp(vcenter.hostname, 443)

    ssh_ok: bool | None = None
    ssh_msg: str | None = None
    if check_ssh:
        ssh_ok, ssh_msg = check_tcp(vcenter.hostname, 22)

    from app.services.scan_engine import ScanEngine

    engine = ScanEngine(settings)
    profiles_ok = engine.profiles_available()
    profiles_msg = (
        f"Baseline profile found at {engine.baseline_profile_path()}"
        if profiles_ok
        else f"Baseline profile missing at {engine.baseline_profile_path()}"
    )

    worker = _check_worker_toolchain(settings)
    cinc_ok = worker["cinc_auditor"]
    saf_ok = worker["saf_cli"]
    cinc_msg = worker["cinc_auditor_message"]
    saf_msg = worker["saf_cli_message"]

    # Full PowerCLI login test runs on the worker during scans, not the web container.
    if api_ok:
        api_msg = (
            f"{api_msg}. Full PowerCLI authentication is verified when a scan runs "
            f"on the scan worker container."
        )

    return PreflightResponse(
        vcenter_api=api_ok,
        vcenter_api_message=api_msg,
        ssh_reachable=ssh_ok,
        ssh_message=ssh_msg,
        profiles_present=profiles_ok,
        profiles_message=profiles_msg,
        cinc_auditor=cinc_ok,
        cinc_auditor_message=cinc_msg,
        saf_cli=saf_ok,
        saf_cli_message=saf_msg,
        worker_reachable=worker.get("worker_reachable", True),
        powercli=worker.get("powercli"),
        powercli_message=worker.get("powercli_message"),
        train_vmware=worker.get("train_vmware"),
        train_vmware_message=worker.get("train_vmware_message"),
    )
