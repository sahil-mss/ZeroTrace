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
