"""Custom exception hierarchy for the Security Testing Engine."""


class SecurityEngineError(Exception):
    """Base exception for all security engine errors."""


class TargetValidationError(SecurityEngineError):
    """Raised when an assessment target violates format or authorization scope."""


class ProfileValidationError(SecurityEngineError):
    """Raised when a requested scan profile is unsupported or misconfigured."""


class ApprovalRequiredError(SecurityEngineError):
    """Raised when an intrusive profile is invoked without required authorization."""


class ScannerExecutionError(SecurityEngineError):
    """Raised when an underlying scanner process fails or crashes."""


class ScannerTimeoutError(SecurityEngineError):
    """Raised when a scanner exceeds its allotted execution window."""


class ScopeViolationError(SecurityEngineError):
    """Raised when an asset or target violates assessment scope or safety policy."""


class AIRecommendationValidationError(SecurityEngineError):
    """Raised when an AI Planner recommendation fails safety, scope, or capability validation."""


class JobLifecycleError(SecurityEngineError):
    """Raised when an invalid state transition or operation occurs on a scan job."""


class ScannerRegistryError(SecurityEngineError):
    """Raised when an unregistered or incompatible scanner is requested."""
