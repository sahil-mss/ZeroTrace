from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import posixpath
from typing import Any, List, Optional, Set, Tuple, Union
from urllib.parse import urlsplit

from aegis_common.enums import AssessmentStatus, ScopeStatus, TargetType, TestPermissionLevel
from aegis_common.models import Assessment, ScopePolicy, ScopeRule
from aegis_common.utils import utc_now


class ScopeReasonCode(str, Enum):
    """Stable, machine-readable reason codes for scope decisions."""
    ALLOWED = "ALLOWED"
    ASSESSMENT_NOT_FOUND = "ASSESSMENT_NOT_FOUND"
    ASSESSMENT_UNAPPROVED = "ASSESSMENT_UNAPPROVED"
    ASSESSMENT_CANCELLED = "ASSESSMENT_CANCELLED"
    ASSESSMENT_COMPLETED = "ASSESSMENT_COMPLETED"
    ASSESSMENT_EXPIRED = "ASSESSMENT_EXPIRED"
    NO_SCOPE_RULES = "NO_SCOPE_RULES"
    MALFORMED_TARGET = "MALFORMED_TARGET"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    EMBEDDED_CREDENTIALS_REJECTED = "EMBEDDED_CREDENTIALS_REJECTED"
    INVALID_PORT = "INVALID_PORT"
    PORT_NOT_PERMITTED = "PORT_NOT_PERMITTED"
    PATH_NOT_PERMITTED = "PATH_NOT_PERMITTED"
    EXCLUDED_TARGET = "EXCLUDED_TARGET"
    SUBDOMAIN_NOT_PERMITTED = "SUBDOMAIN_NOT_PERMITTED"
    LOOKALIKE_NOT_PERMITTED = "LOOKALIKE_NOT_PERMITTED"
    IP_NOT_IN_SCOPE = "IP_NOT_IN_SCOPE"
    TARGET_NOT_IN_SCOPE = "TARGET_NOT_IN_SCOPE"
    REDIRECT_SOURCE_DISALLOWED = "REDIRECT_SOURCE_DISALLOWED"
    REDIRECT_DESTINATION_OUT_OF_SCOPE = "REDIRECT_DESTINATION_OUT_OF_SCOPE"
    REDIRECT_ALLOWED = "REDIRECT_ALLOWED"


class ScopeValidationError(Exception):
    """Raised when a target cannot be parsed or normalized."""
    pass


@dataclass(frozen=True)
class NormalizedTarget:
    """Standardized representation of a validated target candidate."""
    raw: str
    target_type: TargetType
    canonical: str
    hostname: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    effective_port: Optional[int] = None
    path: Optional[str] = None
    ip_object: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
    cidr_object: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None


@dataclass(frozen=True)
class ScopeValidationResult:
    """Structured scope decision record explaining policy enforcement."""
    allowed: bool
    reason_code: ScopeReasonCode
    explanation: str
    normalized_target: Optional[str] = None
    target_type: Optional[TargetType] = None
    effective_host: Optional[str] = None
    effective_port: Optional[int] = None
    effective_path: Optional[str] = None
    matching_rule_id: Optional[str] = None

    @property
    def scope_status(self) -> ScopeStatus:
        return ScopeStatus.IN_SCOPE if self.allowed else ScopeStatus.OUT_OF_SCOPE

    def to_tuple(self) -> Tuple[bool, str, ScopeStatus]:
        """Backward-compatible tuple (is_allowed, explanation, scope_status)."""
        return self.allowed, self.explanation, self.scope_status


def _normalize_hostname(host: str) -> str:
    """
    Normalizes a hostname: strips leading/trailing spaces, trailing DNS dot,
    converts to lowercase, and converts internationalized domain names (IDN) to punycode ASCII.
    """
    clean = host.strip().rstrip(".").lower()
    if not clean:
        raise ScopeValidationError("Hostname cannot be empty.")
    try:
        # Convert IDN to punycode ASCII (e.g. münchen.de -> xn--mnchen-3ya.de)
        clean = clean.encode("idna").decode("ascii")
    except Exception as err:
        raise ScopeValidationError(f"Invalid internationalized hostname '{host}': {err}") from err
    return clean


def _normalize_path(path: str) -> str:
    """Normalizes URL path and resolves relative traversal components."""
    if not path or path == "/":
        return "/"
    # Clean and resolve path traversal components (e.g. /api/v1/../v2 -> /api/v2)
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    # Preserve trailing slash if original path explicitly ended with slash and is not root
    if path.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def normalize_target(target: str) -> NormalizedTarget:
    """
    Parses and standardizes any raw target string (URL, domain, IP, or CIDR).
    Deterministically normalizes hostnames, IP addresses, ports, and paths.
    Raises ScopeValidationError on malformed input.
    """
    if not target or not isinstance(target, str):
        raise ScopeValidationError("Target must be a non-empty string.")

    cleaned = target.strip()
    if not cleaned:
        raise ScopeValidationError("Target cannot be empty or whitespace.")

    # 1. Check for URL schemes
    if "://" in cleaned:
        split_result = urlsplit(cleaned)
        scheme = split_result.scheme.lower()
        if scheme not in ("http", "https"):
            raise ScopeValidationError(
                f"Unsupported URL scheme '{scheme}'. Only 'http' and 'https' are permitted."
            )

        # Check for embedded credentials (RFC 3986 security risk)
        if split_result.username or split_result.password or "@" in split_result.netloc.split(":")[0]:
            raise ScopeValidationError("Embedded user credentials in target URL are prohibited.")

        hostname_raw = split_result.hostname
        if not hostname_raw:
            raise ScopeValidationError(f"Could not extract a valid host from URL: '{target}'")

        port = split_result.port
        if port is not None and not (1 <= port <= 65535):
            raise ScopeValidationError(f"Port {port} is outside valid range 1-65535.")

        effective_port = port if port is not None else (80 if scheme == "http" else 443)
        normalized_path = _normalize_path(split_result.path)

        # Check if the host in URL is an IP address
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(hostname_raw)
            clean_host = str(ip_obj)
            target_type = TargetType.IP_ADDRESS
        except ValueError:
            clean_host = _normalize_hostname(hostname_raw)
            target_type = TargetType.URL

        port_suffix = f":{port}" if port is not None else ""
        canonical = f"{scheme}://{clean_host}{port_suffix}{normalized_path}"

        return NormalizedTarget(
            raw=target,
            target_type=TargetType.URL,
            canonical=canonical,
            scheme=scheme,
            hostname=clean_host,
            port=port,
            effective_port=effective_port,
            path=normalized_path,
            ip_object=ip_obj,
        )

    # 2. Check for CIDR network (e.g. 192.168.1.0/24 or 2001:db8::/32)
    if "/" in cleaned and not cleaned.startswith("/"):
        parts = cleaned.split("/")
        if len(parts) == 2 and parts[1].isdigit():
            try:
                cidr_net = ipaddress.ip_network(cleaned, strict=False)
                return NormalizedTarget(
                    raw=target,
                    target_type=TargetType.CIDR,
                    canonical=str(cidr_net),
                    hostname=str(cidr_net.network_address),
                    cidr_object=cidr_net,
                )
            except ValueError:
                pass  # Fall through to domain/path check

    # 3. Check for IPv6 bracketed address with optional port, e.g. [2001:db8::1]:8080
    if cleaned.startswith("[") and "]" in cleaned:
        bracket_end = cleaned.find("]")
        ip_str = cleaned[1:bracket_end]
        port_part = cleaned[bracket_end + 1:]
        port = None
        if port_part.startswith(":"):
            try:
                port = int(port_part[1:].split("/")[0])
                if not (1 <= port <= 65535):
                    raise ScopeValidationError(f"Port {port} is outside valid range 1-65535.")
            except ValueError as err:
                raise ScopeValidationError(f"Invalid port in IPv6 target '{target}': {err}") from err

        try:
            ip_v6 = ipaddress.IPv6Address(ip_str)
            canonical = f"[{ip_v6.compressed}]" + (f":{port}" if port else "")
            return NormalizedTarget(
                raw=target,
                target_type=TargetType.IP_ADDRESS,
                canonical=canonical,
                hostname=ip_v6.compressed,
                port=port,
                effective_port=port,
                ip_object=ip_v6,
            )
        except ValueError as err:
            raise ScopeValidationError(f"Malformed IPv6 address '{target}': {err}") from err

    # 4. Check for pure IP address (IPv4 or IPv6 without brackets)
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return NormalizedTarget(
            raw=target,
            target_type=TargetType.IP_ADDRESS,
            canonical=ip_obj.compressed if isinstance(ip_obj, ipaddress.IPv6Address) else str(ip_obj),
            hostname=str(ip_obj),
            ip_object=ip_obj,
        )
    except ValueError:
        pass

    # 5. Check for Host:Port or IPv4:Port (e.g. internal.lab:8080 or 127.0.0.1:3000)
    if ":" in cleaned and not cleaned.endswith(":"):
        parts = cleaned.split(":")
        if len(parts) == 2:
            host_candidate = parts[0]
            port_candidate_str = parts[1].split("/")[0]
            path_part = "/" + "/".join(cleaned.split("/")[1:]) if "/" in cleaned else None
            try:
                port = int(port_candidate_str)
                if not (1 <= port <= 65535):
                    raise ScopeValidationError(f"Port {port} is outside valid range 1-65535.")

                # Check if host_candidate is an IP
                ip_obj = None
                try:
                    ip_obj = ipaddress.ip_address(host_candidate)
                    clean_host = str(ip_obj)
                    target_type = TargetType.IP_ADDRESS
                except ValueError:
                    clean_host = _normalize_hostname(host_candidate)
                    target_type = TargetType.DOMAIN

                canonical = f"{clean_host}:{port}" + (path_part or "")
                return NormalizedTarget(
                    raw=target,
                    target_type=target_type,
                    canonical=canonical,
                    hostname=clean_host,
                    port=port,
                    effective_port=port,
                    path=_normalize_path(path_part) if path_part else None,
                    ip_object=ip_obj,
                )
            except ValueError:
                pass  # Not a valid numeric port

    # 6. Domain name with optional path (e.g. lab.example.test or example.com/api)
    host_part = cleaned.split("/")[0]
    path_part = "/" + "/".join(cleaned.split("/")[1:]) if "/" in cleaned else None

    # Check for invalid characters in host
    if " " in host_part or "://" in host_part or "@" in host_part:
        raise ScopeValidationError(f"Malformed hostname '{target}'")

    clean_host = _normalize_hostname(host_part)
    canonical = clean_host + (_normalize_path(path_part) if path_part else "")

    return NormalizedTarget(
        raw=target,
        target_type=TargetType.DOMAIN,
        canonical=canonical,
        hostname=clean_host,
        path=_normalize_path(path_part) if path_part else None,
    )


class ScopeValidator:
    """
    Deterministic Scope and Authorization Enforcement Service for ZeroTrace.
    Evaluates proposed assessment targets, redirect destinations, and resolved IPs
    strictly against approved ScopeRule specifications.
    Network-free, auditable, and cannot be overridden by AI decision-making.
    """

    PERMISSION_HIERARCHY = {
        TestPermissionLevel.PASSIVE_ONLY: 1,
        TestPermissionLevel.ACTIVE_NON_INTRUSIVE: 2,
        TestPermissionLevel.CONTROLLED_VULN_SCAN: 3,
        TestPermissionLevel.INTRUSIVE_TEST: 4,
    }

    @staticmethod
    def canonicalize(raw_target: str) -> dict[str, Any]:
        """
        Legacy adapter method returning a dictionary representation of normalized target.
        """
        norm = normalize_target(raw_target)
        return {
            "raw": norm.raw,
            "scheme": norm.scheme,
            "hostname": norm.hostname,
            "port": norm.port,
            "path": norm.path or "/",
        }

    @classmethod
    def extract_scope_rules(cls, assessment_scope: Any) -> Tuple[Optional[str], List[ScopeRule]]:
        """
        Extracts scope rules and checks assessment lifecycle status.
        Returns: (denial_reason: Optional[str], rules: List[ScopeRule])
        """
        if assessment_scope is None:
            return "Assessment scope is None (fail closed).", []

        # If an Assessment instance is provided, evaluate assessment lifecycle and validity
        if isinstance(assessment_scope, Assessment) or hasattr(assessment_scope, "lifecycle_status"):
            # Check lifecycle status
            status = getattr(assessment_scope, "lifecycle_status", None) or getattr(assessment_scope, "status", None)
            if status != AssessmentStatus.APPROVED and status != AssessmentStatus.ACTIVE:
                return (
                    f"Assessment status is '{status}'. Only APPROVED or ACTIVE assessments permit execution.",
                    [],
                )

            # Check expiration
            expires_at = getattr(assessment_scope, "expires_at", None)
            if expires_at is not None:
                now = utc_now()
                # Ensure tz-aware comparison
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if now > expires_at:
                    return f"Assessment expired on {expires_at.isoformat()} (fail closed).", []

            # Retrieve scope rules
            rules = getattr(assessment_scope, "scope_rules", None)
            if rules:
                return None, list(rules)

            # Fall back to scope policy if scope_rules is empty
            policy = getattr(assessment_scope, "scope", None)
            if policy:
                return None, cls._convert_policy_to_rules(policy)

            return "Assessment has no approved scope rules.", []

        # If a ScopePolicy instance is provided directly
        if isinstance(assessment_scope, ScopePolicy):
            return None, cls._convert_policy_to_rules(assessment_scope)

        # If already a list of ScopeRule objects
        if isinstance(assessment_scope, list):
            return None, [r for r in assessment_scope if isinstance(r, ScopeRule)]

        return f"Unsupported assessment_scope type: {type(assessment_scope)}", []

    @classmethod
    def _convert_policy_to_rules(cls, policy: ScopePolicy) -> List[ScopeRule]:
        """Converts legacy aggregated ScopePolicy to discrete ScopeRule objects."""
        rules: List[ScopeRule] = []
        for d in policy.target_domains:
            clean = d.strip().lower().rstrip(".")
            inc_sub = clean.startswith("*.")
            val = clean[2:] if inc_sub else clean
            rules.append(
                ScopeRule(
                    target_type=TargetType.DOMAIN,
                    target_value=val,
                    include_subdomains=inc_sub,
                    approved_ports=policy.allowed_ports,
                )
            )
        for ip in policy.target_ips:
            rules.append(
                ScopeRule(
                    target_type=TargetType.IP_ADDRESS,
                    target_value=ip.strip(),
                    approved_ports=policy.allowed_ports,
                )
            )
        for cidr in policy.target_cidrs:
            rules.append(
                ScopeRule(
                    target_type=TargetType.CIDR,
                    target_value=cidr.strip(),
                    approved_ports=policy.allowed_ports,
                )
            )
        for url in policy.target_urls:
            rules.append(
                ScopeRule(
                    target_type=TargetType.URL,
                    target_value=url.strip(),
                    approved_ports=policy.allowed_ports,
                )
            )
        for excl in policy.excluded_targets:
            rules.append(
                ScopeRule(
                    target_type=TargetType.DOMAIN,
                    target_value=excl.strip(),
                    is_excluded=True,
                )
            )
        return rules

    @classmethod
    def validate_target(cls, target: str, assessment_scope: Any) -> ScopeValidationResult:
        """
        Deterministically evaluates a target against an Assessment or approved scope rules.
        Returns a rich ScopeValidationResult with decision, reason code, and explanation.
        """
        # 1. Parse and normalize the target
        try:
            norm = normalize_target(target)
        except ScopeValidationError as err:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.MALFORMED_TARGET,
                explanation=f"Malformed target '{target}': {err}",
            )

        # 2. Extract and validate assessment scope
        denial_reason, rules = cls.extract_scope_rules(assessment_scope)
        if denial_reason:
            if "expired" in denial_reason:
                code = ScopeReasonCode.ASSESSMENT_EXPIRED
            elif "status" in denial_reason:
                code = ScopeReasonCode.ASSESSMENT_UNAPPROVED
            elif "None" in denial_reason:
                code = ScopeReasonCode.ASSESSMENT_NOT_FOUND
            else:
                code = ScopeReasonCode.NO_SCOPE_RULES
            return ScopeValidationResult(
                allowed=False,
                reason_code=code,
                explanation=denial_reason,
                normalized_target=norm.canonical,
                target_type=norm.target_type,
            )

        if not rules:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.NO_SCOPE_RULES,
                explanation="No scope rules found for assessment (fail closed).",
                normalized_target=norm.canonical,
                target_type=norm.target_type,
            )

        # Separate rules into exclusions and allow rules
        exclusions = [r for r in rules if r.is_excluded]
        allow_rules = [r for r in rules if not r.is_excluded]

        # 3. Check Exclusion Rules (Immediate Hard Deny)
        for excl in exclusions:
            if cls._matches_rule(norm, excl):
                return ScopeValidationResult(
                    allowed=False,
                    reason_code=ScopeReasonCode.EXCLUDED_TARGET,
                    explanation=f"Target '{norm.canonical}' matches explicit exclusion rule '{excl.target_value}'.",
                    normalized_target=norm.canonical,
                    target_type=norm.target_type,
                    effective_host=norm.hostname,
                    effective_port=norm.effective_port,
                    effective_path=norm.path,
                    matching_rule_id=excl.rule_id,
                )

        # 4. Check Allow Rules
        subdomain_denied_reason = None
        port_denied_reason = None
        path_denied_reason = None

        for rule in allow_rules:
            matches_host, sub_denied = cls._matches_host(norm, rule)
            if not matches_host:
                if sub_denied:
                    subdomain_denied_reason = sub_denied
                continue

            # Host matched! Now check port
            if rule.approved_ports and norm.effective_port is not None:
                if norm.effective_port not in rule.approved_ports:
                    port_denied_reason = (
                        f"Effective port {norm.effective_port} is not in approved ports {rule.approved_ports} for rule '{rule.target_value}'."
                    )
                    continue

            # Check path prefix
            if rule.permitted_path_prefixes and norm.path is not None:
                if not any(norm.path.startswith(prefix) for prefix in rule.permitted_path_prefixes):
                    path_denied_reason = (
                        f"Path '{norm.path}' does not match any permitted prefixes {rule.permitted_path_prefixes}."
                    )
                    continue

            # Target fully satisfied this rule!
            return ScopeValidationResult(
                allowed=True,
                reason_code=ScopeReasonCode.ALLOWED,
                explanation=f"Target '{norm.canonical}' is authorized by scope rule '{rule.target_value}'.",
                normalized_target=norm.canonical,
                target_type=norm.target_type,
                effective_host=norm.hostname,
                effective_port=norm.effective_port,
                effective_path=norm.path,
                matching_rule_id=rule.rule_id,
            )

        # Determine most specific denial reason
        if subdomain_denied_reason:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.SUBDOMAIN_NOT_PERMITTED,
                explanation=subdomain_denied_reason,
                normalized_target=norm.canonical,
                target_type=norm.target_type,
                effective_host=norm.hostname,
            )
        if port_denied_reason:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.PORT_NOT_PERMITTED,
                explanation=port_denied_reason,
                normalized_target=norm.canonical,
                target_type=norm.target_type,
                effective_host=norm.hostname,
                effective_port=norm.effective_port,
            )
        if path_denied_reason:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.PATH_NOT_PERMITTED,
                explanation=path_denied_reason,
                normalized_target=norm.canonical,
                target_type=norm.target_type,
                effective_host=norm.hostname,
                effective_path=norm.path,
            )

        return ScopeValidationResult(
            allowed=False,
            reason_code=ScopeReasonCode.TARGET_NOT_IN_SCOPE,
            explanation=f"Target '{norm.canonical}' is not within any approved domain, IP, or CIDR range.",
            normalized_target=norm.canonical,
            target_type=norm.target_type,
            effective_host=norm.hostname,
        )

    @classmethod
    def _matches_rule(cls, norm: NormalizedTarget, rule: ScopeRule) -> bool:
        """Helper checking if a normalized target matches an exclusion rule."""
        matches, _ = cls._matches_host(norm, rule)
        return matches

    @classmethod
    def _matches_host(cls, norm: NormalizedTarget, rule: ScopeRule) -> Tuple[bool, Optional[str]]:
        """
        Evaluates hostname or IP match between target and rule.
        Returns (matches: bool, subdomain_denial_reason: Optional[str]).
        """
        # Rule is an IP Address
        if rule.target_type == TargetType.IP_ADDRESS:
            if norm.ip_object is not None:
                try:
                    rule_ip = ipaddress.ip_address(rule.target_value)
                    return (norm.ip_object == rule_ip), None
                except ValueError:
                    return False, None
            return False, None

        # Rule is a CIDR block
        if rule.target_type == TargetType.CIDR:
            if norm.ip_object is not None:
                try:
                    rule_net = ipaddress.ip_network(rule.target_value, strict=False)
                    return (norm.ip_object in rule_net), None
                except ValueError:
                    return False, None
            return False, None

        # Rule is a Domain
        if rule.target_type == TargetType.DOMAIN:
            rule_host = rule.target_value.lower().rstrip(".")
            # Exact hostname match
            if norm.hostname == rule_host:
                return True, None

            # Subdomain check: target must end with '.<rule_host>'
            if norm.hostname.endswith("." + rule_host):
                if rule.include_subdomains:
                    return True, None
                return False, f"Subdomain '{norm.hostname}' denied. include_subdomains is not enabled for '{rule_host}'."

            # Explicit check against substring lookalikes (e.g. another-example.test)
            return False, None

        # Rule is a URL
        if rule.target_type == TargetType.URL:
            try:
                rule_url_norm = normalize_target(rule.target_value)
                if norm.hostname == rule_url_norm.hostname:
                    # Check port if URL rule defines one
                    if rule_url_norm.port is not None and norm.effective_port != rule_url_norm.effective_port:
                        return False, None
                    # Check path
                    if rule_url_norm.path and rule_url_norm.path != "/":
                        if norm.path is None or not norm.path.startswith(rule_url_norm.path):
                            return False, None
                    return True, None
            except ScopeValidationError:
                return False, None

        return False, None

    @classmethod
    def validate_resolved_ip(cls, ip_address: str, assessment_scope: Any) -> ScopeValidationResult:
        """
        Verifies that a resolved IP address (IPv4 or IPv6) is explicitly authorized
        before network tools send packets, mitigating DNS rebinding and out-of-scope routing risks.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())
        except ValueError:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.MALFORMED_TARGET,
                explanation=f"Malformed IP address '{ip_address}' cannot be validated.",
            )

        denial_reason, rules = cls.extract_scope_rules(assessment_scope)
        if denial_reason:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.ASSESSMENT_UNAPPROVED,
                explanation=denial_reason,
            )

        # 1. Check exclusions
        for rule in rules:
            if rule.is_excluded:
                if rule.target_type == TargetType.IP_ADDRESS:
                    try:
                        if ip_obj == ipaddress.ip_address(rule.target_value):
                            return ScopeValidationResult(
                                allowed=False,
                                reason_code=ScopeReasonCode.EXCLUDED_TARGET,
                                explanation=f"Resolved IP '{ip_address}' matches excluded IP rule '{rule.target_value}'.",
                                normalized_target=str(ip_obj),
                                target_type=TargetType.IP_ADDRESS,
                                matching_rule_id=rule.rule_id,
                            )
                    except ValueError:
                        pass
                elif rule.target_type == TargetType.CIDR:
                    try:
                        net = ipaddress.ip_network(rule.target_value, strict=False)
                        if ip_obj in net:
                            return ScopeValidationResult(
                                allowed=False,
                                reason_code=ScopeReasonCode.EXCLUDED_TARGET,
                                explanation=f"Resolved IP '{ip_address}' falls within excluded CIDR '{rule.target_value}'.",
                                normalized_target=str(ip_obj),
                                target_type=TargetType.IP_ADDRESS,
                                matching_rule_id=rule.rule_id,
                            )
                    except ValueError:
                        pass

        # 2. Check allow rules
        for rule in rules:
            if not rule.is_excluded:
                if rule.target_type == TargetType.IP_ADDRESS:
                    try:
                        if ip_obj == ipaddress.ip_address(rule.target_value):
                            return ScopeValidationResult(
                                allowed=True,
                                reason_code=ScopeReasonCode.ALLOWED,
                                explanation=f"Resolved IP '{ip_address}' is explicitly authorized.",
                                normalized_target=str(ip_obj),
                                target_type=TargetType.IP_ADDRESS,
                                matching_rule_id=rule.rule_id,
                            )
                    except ValueError:
                        pass
                elif rule.target_type == TargetType.CIDR:
                    try:
                        net = ipaddress.ip_network(rule.target_value, strict=False)
                        if ip_obj in net:
                            return ScopeValidationResult(
                                allowed=True,
                                reason_code=ScopeReasonCode.ALLOWED,
                                explanation=f"Resolved IP '{ip_address}' falls within approved CIDR range '{rule.target_value}'.",
                                normalized_target=str(ip_obj),
                                target_type=TargetType.IP_ADDRESS,
                                matching_rule_id=rule.rule_id,
                            )
                    except ValueError:
                        pass

        return ScopeValidationResult(
            allowed=False,
            reason_code=ScopeReasonCode.IP_NOT_IN_SCOPE,
            explanation=f"Resolved IP '{ip_address}' is not within any approved IP or CIDR scope boundary.",
            normalized_target=str(ip_obj),
            target_type=TargetType.IP_ADDRESS,
        )

    @classmethod
    def validate_redirect(
        cls, source_url: str, destination_url: str, assessment_scope: Any
    ) -> ScopeValidationResult:
        """
        Evaluates an HTTP redirect independently against the approved assessment scope.
        A redirect destination never automatically inherits authorization from the source.
        """
        # 1. Source must be in scope
        src_res = cls.validate_target(source_url, assessment_scope)
        if not src_res.allowed:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.REDIRECT_SOURCE_DISALLOWED,
                explanation=f"Redirect source '{source_url}' is not in scope: {src_res.explanation}",
            )

        # 2. Destination must be in scope independently
        dest_res = cls.validate_target(destination_url, assessment_scope)
        if not dest_res.allowed:
            return ScopeValidationResult(
                allowed=False,
                reason_code=ScopeReasonCode.REDIRECT_DESTINATION_OUT_OF_SCOPE,
                explanation=f"Redirect destination '{destination_url}' is outside authorized assessment scope: {dest_res.explanation}",
                normalized_target=dest_res.normalized_target,
            )

        return ScopeValidationResult(
            allowed=True,
            reason_code=ScopeReasonCode.REDIRECT_ALLOWED,
            explanation=f"Redirect from '{source_url}' to '{destination_url}' is fully authorized.",
            normalized_target=dest_res.normalized_target,
            target_type=dest_res.target_type,
            effective_host=dest_res.effective_host,
            effective_port=dest_res.effective_port,
        )

    @classmethod
    def is_in_scope(cls, raw_target: str, scope: Any) -> Tuple[bool, str, ScopeStatus]:
        """
        Backward-compatible check returning (is_allowed, reason, scope_status).
        """
        res = cls.validate_target(raw_target, scope)
        return res.to_tuple()

    @classmethod
    def check_permission(
        cls, requested_level: TestPermissionLevel, allowed_level: TestPermissionLevel
    ) -> Tuple[bool, str]:
        """
        Ensures a tool operation does not exceed the assessment's approved test profile level.
        """
        req_val = cls.PERMISSION_HIERARCHY.get(requested_level, 99)
        allow_val = cls.PERMISSION_HIERARCHY.get(allowed_level, 0)

        if req_val > allow_val:
            return (
                False,
                f"Requested test permission '{requested_level.value}' exceeds assessment permission '{allowed_level.value}'. Intrusive action blocked.",
            )
        return True, "Permission check passed."


# Expose standalone functions matching specification
validate_target = ScopeValidator.validate_target
validate_resolved_ip = ScopeValidator.validate_resolved_ip
validate_redirect = ScopeValidator.validate_redirect
