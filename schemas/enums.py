from enum import Enum


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"
    OTHER = "other"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"
