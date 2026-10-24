"""
aegis_common: Canonical versioned data contracts and schemas for AegisPT.

Shared across:
- Person 1: Backend, Scope Policy & OSINT Intelligence
- Person 2: Security Scanners & Finding Verification
- Person 3: AI Orchestration, Frontend Dashboard & Report Generation
"""

from aegis_common.enums import (
    AssessmentStatus,
    AssetType,
    AuditOutcome,
    DataClassification,
    EvidenceSourceType,
    JobStatus,
    ScopeStatus,
    Severity,
    TargetType,
    TestPermissionLevel,
    VerificationStatus,
)
from aegis_common.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    JobAuditEntry,
    ResourceBudget,
    ScopePolicy,
    ScopeRule,
)
from aegis_common.utils import (
    ensure_utc,
    generate_id,
    sanitize_sensitive_data,
    utc_now,
)

__version__ = "1.0.0"

__all__ = [
    # Models
    "Assessment",
    "ScopeRule",
    "ScopePolicy",
    "Asset",
    "Evidence",
    "Finding",
    "Job",
    "ResourceBudget",
    "JobAuditEntry",
    "AuditEvent",
    # Enums
    "AssessmentStatus",
    "ScopeStatus",
    "TargetType",
    "AssetType",
    "Severity",
    "VerificationStatus",
    "JobStatus",
    "TestPermissionLevel",
    "EvidenceSourceType",
    "DataClassification",
    "AuditOutcome",
    # Utils
    "utc_now",
    "ensure_utc",
    "generate_id",
    "sanitize_sensitive_data",
]
