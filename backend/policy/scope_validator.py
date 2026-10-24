import ipaddress
from urllib.parse import urlparse

from schemas.enums import ScopeStatus, TestPermissionLevel
from schemas.models import ScopePolicy


class ScopeValidationError(Exception):
    """Raised when a target fails scope verification."""
    pass


class ScopeValidator:
    """
    Deterministic Scope and Policy Enforcement Engine.
    Ensures no scanner or tool can ever execute against out-of-scope,
    unauthorized, or forbidden targets.
    """

    PERMISSION_HIERARCHY = {
        TestPermissionLevel.PASSIVE_ONLY: 1,
        TestPermissionLevel.ACTIVE_NON_INTRUSIVE: 2,
        TestPermissionLevel.CONTROLLED_VULN_SCAN: 3,
        TestPermissionLevel.INTRUSIVE_TEST: 4,
    }

    @staticmethod
    def canonicalize(raw_target: str) -> dict[str, str | None]:
        """
        Parses and standardizes any raw target (URL, domain, IP, host:port).
        Returns a dictionary with canonical hostname, port, path, and scheme.
        """
        if not raw_target or not isinstance(raw_target, str):
            raise ScopeValidationError("Target must be a non-empty string.")

        target = raw_target.strip().lower()

        # Handle scheme if present (e.g. http://, https://)
        if "://" in target:
            parsed = urlparse(target)
            scheme = parsed.scheme
            hostname = parsed.hostname or ""
            port = parsed.port
            path = parsed.path or "/"
        elif ":" in target and not target.endswith("]"):  # potential host:port (not pure IPv6)
            # Check if this might be an IPv6 address
            try:
                ipaddress.IPv6Address(target)
                scheme = None
                hostname = target
                port = None
                path = "/"
            except ValueError:
                # Likely host:port or ipv4:port
                parts = target.split(":")
                hostname = parts[0]
                try:
                    port = int(parts[1].split("/")[0])
                except (ValueError, IndexError):
                    port = None
                path = "/" + "/".join(target.split("/")[1:]) if "/" in target else "/"
                scheme = None
        else:
            # Pure domain, IP, or pathless target
            scheme = None
            hostname = target.split("/")[0]
            port = None
            path = "/" + "/".join(target.split("/")[1:]) if "/" in target else "/"

        # Strip trailing dots from hostname (e.g. example.com.)
        hostname = hostname.rstrip(".")

        # Check if hostname is valid
        if not hostname:
            raise ScopeValidationError(f"Could not extract a valid host from: '{raw_target}'")

        return {
            "raw": raw_target,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
        }

    @classmethod
    def is_in_scope(cls, raw_target: str, scope: ScopePolicy) -> tuple[bool, str, ScopeStatus]:
        """
        Evaluates whether a target is permitted under the given ScopePolicy.
        Returns: (is_allowed: bool, reason: str, scope_status: ScopeStatus)
        """
        try:
            canon = cls.canonicalize(raw_target)
        except ScopeValidationError as e:
            return False, f"Malformed target: {str(e)}", ScopeStatus.OUT_OF_SCOPE

        hostname = canon["hostname"]
        port = canon["port"]

        # 1. Port Check: If port is explicitly given, must be in allowed_ports
        if port is not None and scope.allowed_ports:
            if port not in scope.allowed_ports:
                return (
                    False,
                    f"Port {port} is not in allowed_ports list: {scope.allowed_ports}",
                    ScopeStatus.OUT_OF_SCOPE,
                )

        # 2. Excluded targets check (Immediate Hard Deny)
        for excl in scope.excluded_targets:
            try:
                excl_canon = cls.canonicalize(excl)
                if hostname == excl_canon["hostname"]:
                    return (
                        False,
                        f"Target '{hostname}' matches excluded target '{excl}'",
                        ScopeStatus.OUT_OF_SCOPE,
                    )
            except ScopeValidationError:
                if hostname == excl.strip().lower():
                    return (
                        False,
                        f"Target '{hostname}' matches excluded target '{excl}'",
                        ScopeStatus.OUT_OF_SCOPE,
                    )

        # 3. Check if target is an IP or in CIDR
        is_ip = False
        target_ip_obj = None
        try:
            target_ip_obj = ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip and target_ip_obj:
            # Check against target_ips
            for allowed_ip in scope.target_ips:
                try:
                    if target_ip_obj == ipaddress.ip_address(allowed_ip.strip()):
                        return (
                            True,
                            f"Target IP {hostname} is explicitly allowed.",
                            ScopeStatus.IN_SCOPE,
                        )
                except ValueError:
                    continue

            # Check against target_cidrs
            for allowed_cidr in scope.target_cidrs:
                try:
                    net = ipaddress.ip_network(allowed_cidr.strip(), strict=False)
                    if target_ip_obj in net:
                        return (
                            True,
                            f"Target IP {hostname} falls within allowed CIDR {allowed_cidr}.",
                            ScopeStatus.IN_SCOPE,
                        )
                except ValueError:
                    continue

        # 4. Check domain matches and wildcard domains (*.example.com)
        for allowed_domain in scope.target_domains:
            norm_allowed = allowed_domain.strip().lower().rstrip(".")
            if norm_allowed.startswith("*."):
                root_domain = norm_allowed[2:]
                # Matches foo.root_domain or bar.foo.root_domain
                if hostname == root_domain or hostname.endswith("." + root_domain):
                    return (
                        True,
                        f"Target '{hostname}' matches allowed wildcard scope '{norm_allowed}'",
                        ScopeStatus.IN_SCOPE,
                    )
            else:
                if hostname == norm_allowed:
                    return (
                        True,
                        f"Target '{hostname}' is explicitly in scope.",
                        ScopeStatus.IN_SCOPE,
                    )

        # 5. Check target_urls
        for allowed_url in scope.target_urls:
            try:
                u_canon = cls.canonicalize(allowed_url)
                if hostname == u_canon["hostname"]:
                    if port is None or port == u_canon["port"]:
                        return (
                            True,
                            f"Target matched allowed URL host '{allowed_url}'",
                            ScopeStatus.IN_SCOPE,
                        )
            except ScopeValidationError:
                continue

        return (
            False,
            f"Target '{hostname}' is NOT within any authorized domain, IP, or CIDR range.",
            ScopeStatus.OUT_OF_SCOPE,
        )

    @classmethod
    def check_permission(
        cls, requested_level: TestPermissionLevel, allowed_level: TestPermissionLevel
    ) -> tuple[bool, str]:
        """
        Ensures a tool's requested operation does not exceed the assessment's approved permission level.
        """
        req_val = cls.PERMISSION_HIERARCHY.get(requested_level, 99)
        allow_val = cls.PERMISSION_HIERARCHY.get(allowed_level, 0)

        if req_val > allow_val:
            return (
                False,
                f"Requested test permission '{requested_level.value}' exceeds assessment permission '{allowed_level.value}'. Intrusive action blocked.",
            )
        return True, "Permission check passed."
