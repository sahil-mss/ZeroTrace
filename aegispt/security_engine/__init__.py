"""Security Testing Engine for AegisPT (Person 2's Module).

This module manages scanner integrations, target validation, finding
normalization, evidence persistence, safe verification, and lab evaluation.
"""

from typing import Final

from aegispt.security_engine.core.ai_planner_interface import (
    AIPlanRecommendation,
    AIRecommendationValidator,
)
from aegispt.security_engine.core.scope import (
    BaseScopeValidator,
    LocalScopeValidator,
)
from aegispt.security_engine.service import (
    ScannerRegistry,
    ScannerService,
    create_default_scanner_registry,
)

MODULE_NAME: Final[str] = "security_engine"
MODULE_VERSION: Final[str] = "0.1.0"
PERSON_RESPONSIBILITY: Final[str] = "Person 2: Security Testing Engine"

__all__ = [
    "MODULE_NAME",
    "MODULE_VERSION",
    "PERSON_RESPONSIBILITY",
    "ScannerService",
    "ScannerRegistry",
    "create_default_scanner_registry",
    "BaseScopeValidator",
    "LocalScopeValidator",
    "AIPlanRecommendation",
    "AIRecommendationValidator",
]
