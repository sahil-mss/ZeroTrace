"""
Legacy schemas.enums module.
Canonical definitions have moved to `aegis_common.enums`.
Re-exported here for backward compatibility.
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

__all__ = [
    "AssessmentStatus",
    "AssetType",
    "AuditOutcome",
    "DataClassification",
    "EvidenceSourceType",
    "JobStatus",
    "ScopeStatus",
    "Severity",
    "TargetType",
    "TestPermissionLevel",
    "VerificationStatus",
]
