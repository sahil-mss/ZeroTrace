from enum import Enum


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    PENDING_REVIEW = "PENDING_REVIEW"


class AssessmentStatus(str, Enum):
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    EXPIRED = "EXPIRED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class TestPermissionLevel(str, Enum):
    __test__ = False
    PASSIVE_ONLY = "PASSIVE_ONLY"                 # Only passive DNS, CT logs, public search
    ACTIVE_NON_INTRUSIVE = "ACTIVE_NON_INTRUSIVE" # Port scan, safe HTTP headers, banner grabs
    CONTROLLED_VULN_SCAN = "CONTROLLED_VULN_SCAN" # ZAP baseline, Nuclei safe templates
    INTRUSIVE_TEST = "INTRUSIVE_TEST"             # Elevated permission flag required


class TargetType(str, Enum):
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    CIDR = "CIDR"
    URL = "URL"


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    WEB_APPLICATION = "WEB_APPLICATION"
    SERVICE = "SERVICE"
    URL = "URL"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class JobStatus(str, Enum):
    CREATED = "CREATED"
    POLICY_CHECK = "POLICY_CHECK"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    REVIEW = "REVIEW"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


class EvidenceSourceType(str, Enum):
    DNS_LOOKUP = "DNS_LOOKUP"
    CERT_TRANSPARENCY = "CERT_TRANSPARENCY"
    HTTP_FINGERPRINT = "HTTP_FINGERPRINT"
    WEB_CRAWLER = "WEB_CRAWLER"
    SCANNER_NMAP = "SCANNER_NMAP"
    SCANNER_ZAP = "SCANNER_ZAP"
    SCANNER_NUCLEI = "SCANNER_NUCLEI"
    AI_REASONING = "AI_REASONING"
    MANUAL_INPUT = "MANUAL_INPUT"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class AuditOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    CANCELLED = "CANCELLED"
