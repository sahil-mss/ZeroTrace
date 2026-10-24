"""Finding verification subsystem.

Implements safe, non-destructive validation probes, ground truth correlation,
and audit trail recording to verify candidate findings.
"""

from aegispt.security_engine.verification.base import BaseVerifier
from aegispt.security_engine.verification.engine import VerificationEngine
from aegispt.security_engine.verification.models import VerificationRecord
from aegispt.security_engine.verification.plugins import (
    HeaderSecurityVerifier,
    LabGroundTruthVerifier,
    PassiveReflectionVerifier,
)

__all__ = [
    "BaseVerifier",
    "VerificationEngine",
    "VerificationRecord",
    "HeaderSecurityVerifier",
    "PassiveReflectionVerifier",
    "LabGroundTruthVerifier",
]
