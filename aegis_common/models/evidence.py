from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_common.enums import DataClassification, EvidenceSourceType
from aegis_common.utils import ensure_utc, generate_id, sanitize_sensitive_data, utc_now


class Evidence(BaseModel):
    """
    Canonical evidence provenance record capturing an immutable observation.
    Sensitive credentials and raw tokens are strictly redacted upon model validation.
    """
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    evidence_id: str = Field(default_factory=lambda: generate_id("evi"))
    assessment_id: str = Field(..., min_length=3)
    asset_id: str | None = None
    source_name: str = Field(..., min_length=1, alias="tool_name")
    source_type: EvidenceSourceType = Field(...)
    collection_method: str = Field(default="AUTOMATED_PROBE", min_length=2)
    collected_at: datetime = Field(default_factory=utc_now)
    content_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        alias="hash_sha256",
        description="Cryptographic SHA-256 hash of normalized evidence payload"
    )
    raw_payload_ref: str | None = Field(
        default=None,
        description="Optional local filesystem or blob URI where raw tool output is stored"
    )
    sanitized_excerpt: str | None = Field(
        default=None,
        max_length=4096,
        description="Bounded, sanitized text excerpt safe for API transmission"
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured representation of the observation with credentials redacted"
    )
    data_classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
        description="Security classification of the observed evidence"
    )
    tool_version: str | None = Field(default="1.0")
    metadata: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default="1.0", frozen=True)

    @field_validator("collected_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v) or utc_now()

    @field_validator("data", "metadata")
    @classmethod
    def sanitize_payloads(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Automatically redacts credentials, secrets, and authorization tokens."""
        return sanitize_sensitive_data(v)

    @field_validator("sanitized_excerpt")
    @classmethod
    def sanitize_text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        # Basic check to avoid dumping giant blobs into excerpts
        if len(v) > 4096:
            return v[:4093] + "..."
        return v

    @property
    def hash_sha256(self) -> str:
        return self.content_hash

    @hash_sha256.setter
    def hash_sha256(self, val: str) -> None:
        self.content_hash = val

    @property
    def tool_name(self) -> str:
        return self.source_name

    @tool_name.setter
    def tool_name(self, val: str) -> None:
        self.source_name = val
