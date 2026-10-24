"""Audit models for finding verification.

TASK 6: Captures immutable audit log entries for every finding verification attempt,
preserving forensic provenance and reasoning.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field

from aegispt.security_engine.schemas.enums import VerificationStatus


class VerificationRecord(BaseModel):
    """Immutable audit trail entry documenting a finding verification decision."""

    record_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the verification audit record.",
    )
    finding_id: str = Field(
        ...,
        description="ID of the finding that was evaluated.",
    )
    verification_method: str = Field(
        ...,
        description="Identifier of the verification plugin or rule executed.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when verification was performed.",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="IDs of evidence citations evaluated during verification.",
    )
    previous_status: str = Field(
        ...,
        description="Verification status of the finding prior to this evaluation.",
    )
    new_status: VerificationStatus = Field(
        ...,
        description="Resulting verification status (CONFIRMED, LIKELY, FALSE_POSITIVE, UNVERIFIED, NEEDS_REVIEW).",
    )
    reason: str = Field(
        ...,
        description="Detailed explanation justifying the verification verdict.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary telemetry (probed headers, HTTP status, ground truth match details).",
    )
