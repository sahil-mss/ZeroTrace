from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_common.enums import JobStatus, TestPermissionLevel
from aegis_common.utils import ensure_utc, generate_id, utc_now


class ResourceBudget(BaseModel):
    """Execution bounds enforced on a worker/tool job."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: int = Field(default=180, ge=5, le=1800, description="Hard timeout ceiling")
    max_requests_per_minute: int = Field(default=60, ge=1, le=1000)
    max_concurrency: int = Field(default=3, ge=1, le=10)


class JobAuditEntry(BaseModel):
    """Lifecycle transition history log entry."""

    model_config = ConfigDict(extra="forbid")

    from_status: JobStatus | None = None
    to_status: JobStatus
    timestamp: datetime = Field(default_factory=utc_now)
    reason: str | None = None


class Job(BaseModel):
    """
    Canonical Job record representing an isolated, bounded unit of work.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    job_id: str = Field(default_factory=lambda: generate_id("job"))
    assessment_id: str = Field(..., min_length=3)
    task_type: str = Field(
        ..., min_length=2, description="Tool task key (e.g. 'OSINT_DNS', 'ZAP_SCAN')"
    )
    status: JobStatus = Field(default=JobStatus.CREATED, description="Lifecycle status")
    requested_targets: list[str] = Field(
        default_factory=list, description="Explicit targets requested for execution"
    )
    target_input: str = Field(
        default="", description="Primary canonical target string (backward-compatible)"
    )
    permitted_profile: TestPermissionLevel = Field(
        default=TestPermissionLevel.PASSIVE_ONLY, alias="permission_level"
    )
    resource_budget: ResourceBudget = Field(default_factory=ResourceBudget)
    timeout_seconds: int = Field(
        default=180, ge=5, le=1800, description="Backward-compatible timeout shortcut"
    )
    max_retries: int = Field(default=2, ge=0, le=5)
    retry_count: int = Field(default=0, ge=0, le=5, alias="attempt_count")
    cancellation_requested: bool = Field(default=False)
    cancellation_reason: str | None = None
    error_summary: str | None = Field(default=None, alias="error_message")
    result_summary: dict[str, Any] | None = None
    audit_history: list[JobAuditEntry] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    schema_version: str = Field(default="1.0", frozen=True)

    @field_validator("created_at", "started_at", "completed_at")
    @classmethod
    def validate_utc(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v)

    @model_validator(mode="after")
    def sync_target_fields(self) -> "Job":
        # Keep requested_targets and target_input in sync
        if not self.requested_targets and self.target_input:
            self.requested_targets = [self.target_input]
        elif self.requested_targets and not self.target_input:
            self.target_input = self.requested_targets[0]

        # Sync timeout_seconds with resource_budget
        if self.timeout_seconds != self.resource_budget.timeout_seconds:
            self.resource_budget.timeout_seconds = self.timeout_seconds

        return self

    @property
    def permission_level(self) -> TestPermissionLevel:
        return self.permitted_profile

    @permission_level.setter
    def permission_level(self, val: TestPermissionLevel) -> None:
        self.permitted_profile = val

    @property
    def error_message(self) -> str | None:
        return self.error_summary

    @error_message.setter
    def error_message(self, val: str | None) -> None:
        self.error_summary = val
