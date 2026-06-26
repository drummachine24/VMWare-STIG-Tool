import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings, get_settings
from app.models import ScanJob, ScanResult

logger = logging.getLogger(__name__)

SLUG_RE = re.compile(r"[^\w\-.]+", re.ASCII)


def allowed_export_roots(settings: Settings | None = None) -> list[Path]:
    cfg = settings or get_settings()
    roots = [part.strip() for part in cfg.ckl_export_allowed_roots.split(",") if part.strip()]
    return [Path(root) for root in roots]


def normalize_ckl_export_path(path: str, settings: Settings | None = None) -> str:
    raw = (path or "").strip()
    if not raw:
        return ""

    candidate = Path(raw)
    if ".." in candidate.parts:
        raise ValueError("Export path must not contain '..'")

    if not candidate.is_absolute():
        raise ValueError("Export path must be an absolute path inside the container")

    resolved = candidate.resolve()
    for root in allowed_export_roots(settings):
        root_resolved = root.resolve()
        try:
            resolved.relative_to(root_resolved)
            return str(resolved)
        except ValueError:
            continue

    allowed = ", ".join(str(r) for r in allowed_export_roots(settings))
    raise ValueError(f"Export path must be under one of: {allowed}")


def _safe_slug(value: str, max_len: int = 64) -> str:
    slug = SLUG_RE.sub("_", value.strip()).strip("._") or "target"
    return slug[:max_len]


def export_job_ckls(job: ScanJob, results: list[ScanResult]) -> dict:
    export_base = (job.ckl_export_path or "").strip()
    if not export_base:
        return {"skipped": True, "reason": "No CKL export path configured"}

    try:
        export_base = normalize_ckl_export_path(export_base)
    except ValueError as exc:
        logger.warning("Invalid CKL export path for job %s: %s", job.id, exc)
        return {"error": str(exc)}

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    export_dir = Path(export_base) / f"scan-{job.id}-{timestamp}"
    export_dir.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    skipped = 0
    for result in results:
        if not result.ckl_path:
            skipped += 1
            continue
        source = Path(result.ckl_path)
        if not source.exists():
            skipped += 1
            continue
        filename = f"{result.target_type}-{_safe_slug(result.target_name)}.ckl"
        destination = export_dir / filename
        shutil.copy2(source, destination)
        copied.append(str(destination))

    if not copied:
        return {
            "error": "No CKL files were available to export",
            "export_dir": str(export_dir),
            "skipped": skipped,
        }

    logger.info(
        "Exported %s CKL file(s) for scan job %s to %s",
        len(copied),
        job.id,
        export_dir,
    )
    return {
        "export_dir": str(export_dir),
        "files": copied,
        "count": len(copied),
        "skipped": skipped,
    }
