from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import ScanJob, ScanResult, ScanStatus
from app.services.checklist_service import ensure_result_counts
from app.services.result_parser import parse_scan_artifact
from app.services.stig_catalog import get_stig_scan_catalog

logger = logging.getLogger(__name__)


@dataclass
class StatusCounts:
    open: int = 0
    nr: int = 0
    na: int = 0
    nf: int = 0

    def add(self, other: StatusCounts) -> None:
        self.open += other.open
        self.nr += other.nr
        self.na += other.na
        self.nf += other.nf

    def as_dict(self) -> dict[str, int]:
        return {"open": self.open, "nr": self.nr, "na": self.na, "nf": self.nf}

    @property
    def total(self) -> int:
        return self.open + self.nr + self.na + self.nf

    @property
    def reviewed_total(self) -> int:
        return self.open + self.nr + self.nf


@dataclass
class ChecklistMetrics:
    title: str
    counts: StatusCounts = field(default_factory=StatusCounts)
    target_count: int = 0


@dataclass
class DashboardMetrics:
    totals: StatusCounts
    target_count: int
    result_count: int
    checklists: list[ChecklistMetrics]
    has_data: bool


def _target_type_guide_fallback(target_type: str) -> str:
    catalog = get_stig_scan_catalog()
    key_map = {
        "vcenter_product": "vcenter_product",
        "esxi": "esxi",
        "vm": "vm",
        "vcenter_appliance": "vcsa_appliance",
    }
    cat_key = key_map.get(target_type)
    if not cat_key:
        return target_type.replace("_", " ").title()
    guides = catalog.get(cat_key, {}).get("guides") or []
    if guides:
        return guides[0]
    return catalog.get(cat_key, {}).get("label") or target_type


def _counts_from_result(result: ScanResult) -> StatusCounts:
    return StatusCounts(
        open=result.count_open or 0,
        nr=result.count_nr or 0,
        na=result.count_na or 0,
        nf=result.count_nf or 0,
    )


def _counts_from_items(items: list) -> dict[str, StatusCounts]:
    grouped: dict[str, StatusCounts] = defaultdict(StatusCounts)
    for item in items:
        title = (getattr(item, "stig_title", None) or "").strip()
        if not title:
            title = "Unknown checklist"
        status = (getattr(item, "status", None) or "NR").upper()
        bucket = grouped[title]
        if status == "O":
            bucket.open += 1
        elif status == "NA":
            bucket.na += 1
        elif status == "NF":
            bucket.nf += 1
        else:
            bucket.nr += 1
    return grouped


def _latest_completed_results(db: Session) -> list[ScanResult]:
    latest_job_sq = (
        db.query(
            ScanResult.target_type,
            ScanResult.target_name,
            func.max(ScanResult.scan_job_id).label("job_id"),
        )
        .join(ScanJob, ScanJob.id == ScanResult.scan_job_id)
        .filter(ScanJob.status == ScanStatus.COMPLETED.value)
        .group_by(ScanResult.target_type, ScanResult.target_name)
        .subquery()
    )

    return (
        db.query(ScanResult)
        .join(
            latest_job_sq,
            (ScanResult.target_type == latest_job_sq.c.target_type)
            & (ScanResult.target_name == latest_job_sq.c.target_name)
            & (ScanResult.scan_job_id == latest_job_sq.c.job_id),
        )
        .all()
    )


def get_dashboard_metrics(db: Session) -> DashboardMetrics:
    results = _latest_completed_results(db)
    totals = StatusCounts()
    checklist_map: dict[str, ChecklistMetrics] = {}

    for result in results:
        ensure_result_counts(db, result)
        json_path = Path(result.json_path) if result.json_path else None
        ckl_path = Path(result.ckl_path) if result.ckl_path else None
        parsed = parse_scan_artifact(json_path, ckl_path) if (json_path or ckl_path) else None

        if parsed and parsed.items:
            grouped = _counts_from_items(parsed.items)
            for title, counts in grouped.items():
                entry = checklist_map.setdefault(
                    title, ChecklistMetrics(title=title, target_count=0)
                )
                entry.counts.add(counts)
                entry.target_count += 1
            totals.add(_counts_from_result(result))
        elif any([result.count_open, result.count_nr, result.count_na, result.count_nf]):
            counts = _counts_from_result(result)
            totals.add(counts)
            title = _target_type_guide_fallback(result.target_type)
            entry = checklist_map.setdefault(title, ChecklistMetrics(title=title, target_count=0))
            entry.counts.add(counts)
            entry.target_count += 1

    checklists = sorted(
        checklist_map.values(),
        key=lambda row: (row.counts.open + row.counts.nr, row.title),
        reverse=True,
    )

    return DashboardMetrics(
        totals=totals,
        target_count=len(results),
        result_count=len(results),
        checklists=checklists,
        has_data=totals.total > 0,
    )


def metrics_as_dict(metrics: DashboardMetrics) -> dict:
    return {
        "has_data": metrics.has_data,
        "target_count": metrics.target_count,
        "totals": metrics.totals.as_dict(),
        "checklists": [
            {
                "title": row.title,
                "target_count": row.target_count,
                "counts": row.counts.as_dict(),
                "total": row.counts.total,
            }
            for row in metrics.checklists
        ],
    }
