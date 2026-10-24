from enum import Enum

from aegis_common.enums import (
    AuditOutcome,
    DataClassification,
    EvidenceSourceType,
    JobStatus,
    ScopeStatus,
    Severity,
    TargetType,
    TestPermissionLevel,
)


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    # also support uppercase equivalents if passed
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    EXPIRED = "EXPIRED"


class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"
    OTHER = "other"
    # also support uppercase
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    WEB_APPLICATION = "WEB_APPLICATION"
    URL = "URL"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"


__all__ = [
    "AssessmentStatus",
    "AssetType",
    "AuditOutcome",
    "ConfidenceLevel",
    "DataClassification",
    "EvidenceSourceType",
    "FindingSeverity",
    "JobStatus",
    "ScopeStatus",
    "Severity",
    "TargetType",
    "TestPermissionLevel",
    "VerificationStatus",
]
