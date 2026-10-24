"""
Legacy schemas.models module.
Canonical models have moved to `aegis_common.models`.
Re-exported here for backward compatibility.
"""

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

__all__ = [
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
    "utc_now",
    "ensure_utc",
    "generate_id",
    "sanitize_sensitive_data",
]
