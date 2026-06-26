from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ScanTargetType(str, Enum):
    ESXI = "esxi"
    VM = "vm"
    VCENTER_PRODUCT = "vcenter_product"
    VCENTER_APPLIANCE = "vcenter_appliance"


class VCenterConnection(Base):
    __tablename__ = "vcenter_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    api_username: Mapped[str] = mapped_column(String(255), nullable=False)
    api_password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    ssh_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssh_password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="vcenter")
    schedules: Mapped[list["ScanSchedule"]] = relationship(back_populates="vcenter")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vcenter_id: Mapped[int] = mapped_column(ForeignKey("vcenter_connections.id"))
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING.value)
    scan_esxi: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_vms: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_vcenter_product: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_vcenter_appliance: Mapped[bool] = mapped_column(Boolean, default=False)
    esxi_scope: Mapped[str] = mapped_column(String(32), default="all_hosts")
    esxi_cluster: Mapped[str | None] = mapped_column(String(255), nullable=True)
    esxi_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vm_scope: Mapped[str] = mapped_column(String(32), default="all")
    inputs_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    progress_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_current: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    selected_targets_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("scan_schedules.id"), nullable=True)
    ckl_export_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ckl_export_dir: Mapped[str | None] = mapped_column(String(512), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    vcenter: Mapped["VCenterConnection"] = relationship(back_populates="scan_jobs")
    schedule: Mapped["ScanSchedule | None"] = relationship(back_populates="scan_jobs")
    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.COMPLETED.value)
    json_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ckl_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    passed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    count_nf: Mapped[int | None] = mapped_column(Integer, nullable=True)
    count_nr: Mapped[int | None] = mapped_column(Integer, nullable=True)
    count_na: Mapped[int | None] = mapped_column(Integer, nullable=True)
    count_open: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan_job: Mapped["ScanJob"] = relationship(back_populates="results")
    remediation_targets: Mapped[list["RemediationTarget"]] = relationship(
        back_populates="scan_result"
    )


class RemediationJob(Base):
    __tablename__ = "remediation_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    source_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"))
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    vcf_control_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=RemediationStatus.PENDING.value)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_current: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    targets: Mapped[list["RemediationTarget"]] = relationship(
        back_populates="remediation_job", cascade="all, delete-orphan"
    )


class RemediationTarget(Base):
    __tablename__ = "remediation_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    remediation_job_id: Mapped[int] = mapped_column(ForeignKey("remediation_jobs.id"))
    scan_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"))
    target_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=RemediationStatus.PENDING.value)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    remediation_job: Mapped["RemediationJob"] = relationship(back_populates="targets")
    scan_result: Mapped["ScanResult"] = relationship(back_populates="remediation_targets")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    vcenter_id: Mapped[int] = mapped_column(ForeignKey("vcenter_connections.id"))
    cron_expression: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_esxi: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_vms: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_vcenter_product: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_vcenter_appliance: Mapped[bool] = mapped_column(Boolean, default=False)
    esxi_scope: Mapped[str] = mapped_column(String(32), default="all_hosts")
    esxi_cluster: Mapped[str | None] = mapped_column(String(255), nullable=True)
    esxi_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vm_scope: Mapped[str] = mapped_column(String(32), default="all")
    inputs_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    ckl_export_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    vcenter: Mapped["VCenterConnection"] = relationship(back_populates="schedules")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="schedule")
