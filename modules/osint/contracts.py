"""
OSINT Adapter contracts and interfaces for ZeroTrace / AegisPT.

Defines the pluggable adapter specification, execution context, resource budget,
and structured observation data contracts.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from aegis_common.enums import AssetType, EvidenceSourceType, TargetType, TestPermissionLevel
from backend.app.services.scope_validator import ScopeValidator


class CancellationToken:
    """Cooperative cancellation token for bounded job and collection lifecycles."""

    def __init__(self):
        self._is_cancelled: bool = False
        self._reason: str | None = None
        self._callbacks: list[Callable[[str], None]] = []

    def cancel(self, reason: str = "User requested cancellation") -> None:
        self._is_cancelled = True
        self._reason = reason
        for cb in self._callbacks:
            try:
                cb(reason)
            except Exception:
                pass

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled

    @property
    def reason(self) -> str | None:
        return self._reason

    def register_callback(self, callback: Callable[[str], None]) -> None:
        self._callbacks.append(callback)


@dataclass
class OSINTResourceBudget:
    """Resource constraints, timeouts, and rate limits for an OSINT adapter."""

    timeout_seconds: float = 10.0
    max_response_bytes: int = 1_000_000  # 1 MB default ceiling
    rate_limit_per_minute: int = 60
    max_results_per_target: int = 100


@dataclass
class OSINTRawObservation:
    """Structured individual observation yielded by an OSINT adapter."""

    target: str
    target_type: TargetType | AssetType | None = None
    confidence: float = 1.0
    data: dict[str, Any] = field(default_factory=dict)
    raw_payload: bytes | str | None = None
    sanitized_excerpt: str | None = None
    relationships: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at: datetime | None = None


@dataclass
class OSINTAdapterResult:
    """Execution summary and structured findings returned by an OSINT adapter."""

    adapter_name: str
    adapter_version: str
    success: bool
    observations: list[OSINTRawObservation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0


@dataclass
class OSINTCollectionContext:
    """Execution context provided to OSINT adapters."""

    assessment_id: str
    approved_targets: list[str]
    scope_validator: ScopeValidator
    cancellation_token: CancellationToken = field(default_factory=CancellationToken)
    session: Session | None = None
    permission_level: TestPermissionLevel = TestPermissionLevel.PASSIVE_ONLY
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseOSINTAdapter(ABC):
    """
    Abstract base class / pluggable interface for passive OSINT adapters.
    Each adapter must be deterministic, bounded by resource budgets,
    and return structured findings.
    """

    adapter_name: str = "base_osint"
    adapter_version: str = "1.0.0"
    description: str = "Base OSINT Adapter"
    source_type: EvidenceSourceType = EvidenceSourceType.DNS_LOOKUP
    supported_target_types: list[TargetType] = field(default_factory=lambda: [TargetType.DOMAIN])
    is_passive: bool = True
    required_permission: TestPermissionLevel = TestPermissionLevel.PASSIVE_ONLY
    resource_budget: OSINTResourceBudget = field(default_factory=OSINTResourceBudget)
    enabled: bool = True

    @abstractmethod
    async def collect(self, target: str, context: OSINTCollectionContext) -> OSINTAdapterResult:
        """
        Executes passive reconnaissance against an approved in-scope target.
        Must honor context.cancellation_token and self.resource_budget.
        """
        pass
