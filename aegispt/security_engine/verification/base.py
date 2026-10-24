"""Modular verification plugin interface.

TASK 3: Defines the contract that all concrete verification plugins must fulfill.
Enforces non-destructive, low-impact checks and prohibits arbitrary exploitation.
"""

from abc import ABC, abstractmethod
from typing import Any
import requests

from aegispt.security_engine.schemas.enums import (
    ImpactLevel,
    PermissionLevel,
    VerificationStatus,
)
from aegispt.security_engine.schemas.finding import NormalizedFinding


class BaseVerifier(ABC):
    """Abstract base class for modular finding verification plugins."""

    @property
    @abstractmethod
    def verification_id(self) -> str:
        """Unique identifier for this verification plugin (e.g. 'verifier_header_security')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def supported_finding_types(self) -> list[str]:
        """CWE numbers or vulnerability categories supported by this verifier."""
        raise NotImplementedError

    @property
    @abstractmethod
    def preconditions(self) -> list[str]:
        """Prerequisites required to execute verification (e.g. ['local_target', 'http_url'])."""
        raise NotImplementedError

    @property
    @abstractmethod
    def required_permission_level(self) -> PermissionLevel:
        """Permission tier required for this verification method."""
        raise NotImplementedError

    @property
    @abstractmethod
    def evidence_requirements(self) -> list[str]:
        """Required evidence attributes or metadata keys."""
        raise NotImplementedError

    @property
    @abstractmethod
    def potential_impact(self) -> ImpactLevel:
        """Estimated operational impact of running this verification method."""
        raise NotImplementedError

    @abstractmethod
    def verify(
        self,
        finding: NormalizedFinding,
        session: requests.Session | None = None,
    ) -> tuple[VerificationStatus, str, dict[str, Any]]:
        """Evaluate finding evidence and return (VerificationStatus, reason, metadata).

        SAFETY CONTRACT:
        - Must NOT execute destructive attacks or write payloads.
        - Must use benign, non-destructive low-impact validation probes.
        """
        raise NotImplementedError
