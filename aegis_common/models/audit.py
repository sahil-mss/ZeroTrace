import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_common.enums import AuditOutcome
from aegis_common.utils import ensure_utc, generate_id, sanitize_sensitive_data, utc_now


class AuditEvent(BaseModel):
    """
    Append-only immutable audit trail record for compliance, non-repudiation,
    and security policy verification.
    """
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    event_id: str = Field(default_factory=lambda: generate_id("evt"))
    assessment_id: str = Field(..., min_length=3)
    job_id: str | None = None
    event_type: str = Field(..., min_length=2, description="Categorical event code (e.g. 'SCOPE_CHECK_REJECTED')")
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str = Field(default="system", min_length=1, description="Operator username or automated component")
    outcome: AuditOutcome = Field(default=AuditOutcome.SUCCESS)
    correlation_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    sanitized_metadata: dict[str, Any] = Field(
        default_factory=dict,
        alias="details",
        description="Structured operational context with credentials automatically redacted"
    )
    schema_version: str = Field(default="1.0", frozen=True)

    @field_validator("timestamp")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v) or utc_now()

    @field_validator("sanitized_metadata")
    @classmethod
    def sanitize_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        return sanitize_sensitive_data(v)

    @property
    def details(self) -> dict[str, Any]:
        return self.sanitized_metadata

    @details.setter
    def details(self, val: dict[str, Any]) -> None:
        self.sanitized_metadata = val
