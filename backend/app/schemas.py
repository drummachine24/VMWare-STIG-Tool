from datetime import datetime

from pydantic import BaseModel, Field


class VCenterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    api_username: str
    api_password: str
    ssh_username: str | None = "root"
    ssh_password: str | None = None


class VCenterCredentialsUpdate(BaseModel):
    api_username: str | None = None
    api_password: str | None = None
    ssh_username: str | None = None
    ssh_password: str | None = None


class VCenterResponse(BaseModel):
    id: int
    name: str
    hostname: str
    api_username: str
    ssh_username: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanJobCreate(BaseModel):
    name: str
    vcenter_id: int
    scan_esxi: bool = True
    scan_vms: bool = True
    scan_vcenter_product: bool = True
    scan_vcenter_appliance: bool = False
    esxi_scope: str = "all_hosts"
    esxi_cluster: str | None = None
    esxi_host: str | None = None
    vm_scope: str = "all"
    inputs_yaml: str | None = None
    selected_targets_json: str | None = None


class ScanJobResponse(BaseModel):
    id: int
    name: str
    vcenter_id: int
    status: str
    scan_esxi: bool
    scan_vms: bool
    scan_vcenter_product: bool
    scan_vcenter_appliance: bool
    error_message: str | None
    progress_message: str | None = None
    progress_current: int = 0
    progress_total: int = 0
    cancel_requested: bool = False
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResultResponse(BaseModel):
    id: int
    target_type: str
    target_name: str
    status: str
    json_path: str | None
    ckl_path: str | None
    passed: int | None
    failed: int | None
    skipped: int | None
    count_nf: int | None = None
    count_nr: int | None = None
    count_na: int | None = None
    count_open: int | None = None
    summary: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanProgressResponse(BaseModel):
    id: int
    status: str
    progress_message: str | None
    progress_current: int
    progress_total: int
    cancel_requested: bool
    error_message: str | None
    results: list[ScanResultResponse]


class StigPreviewRequest(BaseModel):
    vcenter_id: int
    selected_targets_json: str | None = None
    scan_esxi: bool = False
    scan_vms: bool = False
    scan_vcenter_product: bool = False
    scan_vcenter_appliance: bool = False
    esxi_scope: str = "all_hosts"
    esxi_cluster: str | None = None
    esxi_host: str | None = None


class StigPreviewStep(BaseModel):
    target: str
    type: str
    transport: str
    profile: str
    guides: list[str]
    estimated: bool = False


class StigPreviewGuide(BaseModel):
    title: str
    audit_count: int


class StigPreviewResponse(BaseModel):
    step_count: int
    steps: list[StigPreviewStep]
    guides: list[StigPreviewGuide]
    empty: bool
    catalog: dict | None = None


class ScheduleCreate(BaseModel):
    name: str
    vcenter_id: int
    cron_expression: str = "0 2 * * 0"
    enabled: bool = True
    scan_esxi: bool = True
    scan_vms: bool = True
    scan_vcenter_product: bool = True
    scan_vcenter_appliance: bool = False
    esxi_scope: str = "all_hosts"
    esxi_cluster: str | None = None
    esxi_host: str | None = None
    vm_scope: str = "all"
    inputs_yaml: str | None = None
    ckl_export_path: str | None = None


class ScheduleResponse(BaseModel):
    id: int
    name: str
    vcenter_id: int
    cron_expression: str
    enabled: bool
    scan_esxi: bool
    scan_vms: bool
    scan_vcenter_product: bool
    scan_vcenter_appliance: bool
    ckl_export_path: str | None = None
    last_run_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PreflightResponse(BaseModel):
    vcenter_api: bool
    vcenter_api_message: str
    ssh_reachable: bool | None
    ssh_message: str | None
    profiles_present: bool
    profiles_message: str
    cinc_auditor: bool
    cinc_auditor_message: str = ""
    saf_cli: bool
    saf_cli_message: str = ""
    worker_reachable: bool = True
    powercli: bool | None = None
    powercli_message: str | None = None
    train_vmware: bool | None = None
    train_vmware_message: str | None = None


class RemediationPeerResponse(BaseModel):
    result_id: int
    target_name: str
    target_type: str
    is_current: bool
    selected: bool = True


class RemediationPeersResponse(BaseModel):
    rule_id: str
    control_id: str = ""
    vcf_control_id: str = ""
    target_type: str
    source_result_id: int
    peers: list[RemediationPeerResponse]
    remediable: bool = False


class RemediationRequest(BaseModel):
    rule_id: str
    control_id: str = ""
    vcf_control_id: str = ""
    target_result_ids: list[int] = Field(min_length=1)


class RemediationTargetResponse(BaseModel):
    id: int
    scan_result_id: int
    target_name: str
    status: str
    message: str | None = None
    log_path: str | None = None

    model_config = {"from_attributes": True}


class RemediationJobResponse(BaseModel):
    id: int
    scan_job_id: int
    source_result_id: int
    rule_id: str
    vcf_control_id: str
    target_type: str
    status: str
    error_message: str | None = None
    progress_message: str | None = None
    progress_current: int = 0
    progress_total: int = 0
    targets: list[RemediationTargetResponse] = Field(default_factory=list)
    created_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}
