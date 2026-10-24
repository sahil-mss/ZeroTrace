"""Scope enforcement contracts and provisional local scope validator.

TASK 2: Integration with Person 1's authoritative scope enforcement.
Provides an abstract base interface for Person 1's scope policy engine and a strict
provisional LocalScopeValidator that guarantees zero external network leakage.

CRITICAL SECURITY RULE:
AI-generated targets or recommendations from Person 3 are NEVER treated as authoritative.
All targets must pass validation through this scope interface before any scanner process
is initiated.
"""

from abc import ABC, abstractmethod
from ipaddress import ip_address, ip_network
from typing import Iterable
from urllib.parse import urlparse

from aegispt.security_engine.core.exceptions import ScopeViolationError
from aegispt.security_engine.schemas.enums import AssetType
from aegispt.security_engine.schemas.target import ScanTarget

# Predefined safe local subnets
_SAFE_LOCAL_NETWORKS = [
    ip_network("127.0.0.0/8"),       # IPv4 Loopback
    ip_network("10.0.0.0/8"),        # Private Class A
    ip_network("172.16.0.0/12"),     # Private Class B (including Docker bridge default)
    ip_network("192.168.0.0/16"),    # Private Class C
    ip_network("::1/128"),           # IPv6 Loopback
    ip_network("fc00::/7"),          # IPv6 Unique Local Address
]

_SAFE_LOCAL_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "juice-shop",
    "local-lab",
}


class BaseScopeValidator(ABC):
    """Abstract scope validator interface.

    Person 1 provides the authoritative implementation backed by assessment rules,
    asset inventories, and explicit customer scope contracts.
    """

    @abstractmethod
    def validate_target(self, target: ScanTarget, assessment_id: str | None = None) -> bool:
        """Validate whether a target is permitted for the given assessment.

        Returns True if target is strictly within authorized scope.
        Raises ScopeViolationError if the target violates scope boundaries.
        """
        raise NotImplementedError

    def validate_scope(self, target: ScanTarget, assessment_id: str | None = None) -> bool:
        """Alias for validate_target matching Person 1's scope interface."""
        return self.validate_target(target, assessment_id)

    def is_in_scope(self, target: ScanTarget, assessment_id: str | None = None) -> bool:
        """Boolean check whether target is within scope."""
        try:
            return self.validate_target(target, assessment_id)
        except ScopeViolationError:
            return False


class LocalScopeValidator(BaseScopeValidator):
    """Provisional scope validator enforcing strict local lab boundaries.

    Ensures that security engine operations are strictly confined to localhost,
    private test subnets, and explicitly approved local lab domains.
    """

    def __init__(
        self,
        allowed_domains: Iterable[str] | None = None,
        allowed_networks: Iterable[str] | None = None,
        enforce_local_only: bool = True,
    ) -> None:
        """Initialize validator with optional custom local whitelists.

        Args:
            allowed_domains: Additional permitted local domain names.
            allowed_networks: Additional permitted IP networks in CIDR format.
            enforce_local_only: If True, blocks any publicly routable IP address.
        """
        self.allowed_domains = set(_SAFE_LOCAL_DOMAINS)
        if allowed_domains:
            self.allowed_domains.update(d.lower().strip() for d in allowed_domains)

        self.allowed_networks = list(_SAFE_LOCAL_NETWORKS)
        if allowed_networks:
            for net_str in allowed_networks:
                self.allowed_networks.append(ip_network(net_str, strict=False))

        self.enforce_local_only = enforce_local_only

    def _is_ip_allowed(self, ip_str: str) -> bool:
        """Check if an IP address belongs to permitted local/private subnets."""
        try:
            ip = ip_address(ip_str.strip())
            return any(ip in net for net in self.allowed_networks)
        except ValueError:
            return False

    def validate_target(self, target: ScanTarget, assessment_id: str | None = None) -> bool:
        """Validate target against scope boundaries and local safety guardrails.

        Raises ScopeViolationError if the target is out of scope or targets public hosts.
        """
        # Rule 1: Target must have explicit is_in_scope flag set to True
        if not target.is_in_scope:
            raise ScopeViolationError(
                f"Target '{target.target_value}' is explicitly flagged as out of scope "
                f"(is_in_scope=False) for assessment '{assessment_id or 'UNSPECIFIED'}'."
            )

        val = target.target_value.strip()

        # Rule 2: Shell metacharacter guard
        forbidden = [";", "&", "|", "`", "$", "\n", "\r", "<", ">", "(", ")"]
        if any(c in val for c in forbidden):
            raise ScopeViolationError(
                f"Target '{val}' contains forbidden characters or command separators."
            )

        # Rule 3: Asset type specific validation
        if target.asset_type == AssetType.IP_ADDRESS:
            # Safely strip port if present (e.g. 127.0.0.1:8080)
            ip_val = val.split(":")[0] if ":" in val and "." in val else val
            if not self._is_ip_allowed(ip_val):
                raise ScopeViolationError(
                    f"IP address '{val}' is not in permitted local/private networks "
                    f"for assessment '{assessment_id or 'LOCAL_LAB'}'."
                )

        elif target.asset_type == AssetType.CIDR_RANGE:
            try:
                net = ip_network(val, strict=False)
                if not any(net.subnet_of(safe_net) for safe_net in self.allowed_networks):
                    raise ScopeViolationError(
                        f"CIDR range '{val}' is outside permitted local/private subnets."
                    )
            except ValueError as exc:
                raise ScopeViolationError(f"Invalid CIDR range '{val}': {exc}") from exc

        elif target.asset_type == AssetType.WEB_URL:
            try:
                parsed = urlparse(val)
                hostname = parsed.hostname
                if not hostname:
                    raise ScopeViolationError(f"Web URL '{val}' has no valid hostname.")

                hostname_clean = hostname.lower().strip()
                # Check domain whitelist or IP resolution
                if hostname_clean in self.allowed_domains:
                    pass
                elif self._is_ip_allowed(hostname_clean):
                    pass
                else:
                    raise ScopeViolationError(
                        f"Target URL host '{hostname_clean}' is not in the approved local lab domains."
                    )
            except Exception as exc:
                if isinstance(exc, ScopeViolationError):
                    raise
                raise ScopeViolationError(f"Malformed target URL '{val}': {exc}") from exc

        elif target.asset_type == AssetType.HOSTNAME:
            hostname_clean = val.lower().strip()
            if hostname_clean not in self.allowed_domains and not self._is_ip_allowed(hostname_clean):
                raise ScopeViolationError(
                    f"Hostname '{val}' is not in approved local domains list."
                )

        elif target.asset_type == AssetType.PORT_SERVICE:
            host_part = val.split(":")[0].lower().strip() if ":" in val else val.lower().strip()
            if host_part not in self.allowed_domains and not self._is_ip_allowed(host_part):
                raise ScopeViolationError(
                    f"Port service host '{host_part}' is not in approved local domains or IP subnets."
                )

        return True
