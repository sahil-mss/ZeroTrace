"""
Scope Validation Policy Module for ZeroTrace.
Canonical implementation lives in `backend.app.services.scope_validator`.
Re-exported here for complete backward compatibility.
"""

from backend.app.services.scope_validator import (
    NormalizedTarget,
    ScopeReasonCode,
    ScopeValidationError,
    ScopeValidationResult,
    ScopeValidator,
    normalize_target,
    validate_redirect,
    validate_resolved_ip,
    validate_target,
)

__all__ = [
    "ScopeValidator",
    "ScopeValidationError",
    "ScopeValidationResult",
    "ScopeReasonCode",
    "NormalizedTarget",
    "normalize_target",
    "validate_target",
    "validate_resolved_ip",
    "validate_redirect",
]
