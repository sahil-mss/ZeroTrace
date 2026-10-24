from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_common.enums import AssetType, ScopeStatus
from aegis_common.utils import ensure_utc, generate_id, utc_now


class Asset(BaseModel):
    """
    Canonical record of a discovered or configured resource within or adjacent to scope.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    asset_id: str = Field(default_factory=lambda: generate_id("asset"))
    assessment_id: str = Field(..., min_length=3)
    asset_type: AssetType = Field(...)
    normalized_value: str = Field(
        ..., min_length=1, alias="value", description="Standardized host, IP, or URL"
    )
    scope_classification: ScopeStatus = Field(
        default=ScopeStatus.PENDING_REVIEW,
        alias="scope_status",
        description="Scope verification determination",
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_evidence_ids: list[str] = Field(default_factory=list)
    is_inferred: bool = Field(
        default=False, description="True if asset was logically deduced; False if directly observed"
    )
    directly_observed: bool = Field(
        default=True, description="Flag indicating direct tool or OSINT observation"
    )
    relationships: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Associated graph relationships, e.g. {'subdomain_of': ['example.test']}",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=utc_now, alias="first_observed")
    last_seen: datetime = Field(default_factory=utc_now, alias="last_observed")
    schema_version: str = Field(default="1.0", frozen=True)

    @field_validator("asset_type", mode="before")
    @classmethod
    def normalize_asset_type(cls, v: object) -> object:
        if hasattr(v, "value"):
            v = v.value
        if isinstance(v, str):
            v_upper = v.strip().upper()
            mapping = {
                "DOMAIN": AssetType.DOMAIN,
                "SUBDOMAIN": AssetType.SUBDOMAIN,
                "IP": AssetType.IP_ADDRESS,
                "IP_ADDRESS": AssetType.IP_ADDRESS,
                "WEB_APP": AssetType.WEB_APPLICATION,
                "WEB_APPLICATION": AssetType.WEB_APPLICATION,
                "SERVICE": AssetType.SERVICE,
                "API_ENDPOINT": AssetType.WEB_APPLICATION,
                "URL": AssetType.URL,
            }
            if v_upper in mapping:
                return mapping[v_upper]
            if v_upper in AssetType.__members__:
                return AssetType[v_upper]
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence score {v} must be between 0.0 and 1.0 inclusive.")
        return round(v, 4)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v) or utc_now()

    @model_validator(mode="after")
    def sync_observation_flags(self) -> "Asset":
        # Keep is_inferred and directly_observed synchronized
        if self.is_inferred and self.directly_observed:
            self.directly_observed = False
        return self

    @property
    def value(self) -> str:
        return self.normalized_value

    @value.setter
    def value(self, val: str) -> None:
        self.normalized_value = val

    @property
    def scope_status(self) -> ScopeStatus:
        return self.scope_classification

    @scope_status.setter
    def scope_status(self, val: ScopeStatus) -> None:
        self.scope_classification = val

    @property
    def first_observed(self) -> datetime:
        return self.first_seen

    @property
    def last_observed(self) -> datetime:
        return self.last_seen

    @last_observed.setter
    def last_observed(self, val: datetime) -> None:
        self.last_seen = val
