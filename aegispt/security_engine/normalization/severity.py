"""Explicit severity mapping services.

TASK 4: Standardizes raw tool severities to the common Severity enum while
strictly preserving original scanner values. Disallows assuming Nmap service
discovery and ZAP vulnerability alerts share identical semantics.
"""

from typing import Any
from aegispt.security_engine.schemas.enums import Severity


class SeverityMapper:
    """Manages tool-specific severity translations."""

    # Explicit ZAP severity mapping
    ZAP_RISK_MAP: dict[str, Severity] = {
        "3": Severity.HIGH,
        "high": Severity.HIGH,
        "2": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "1": Severity.LOW,
        "low": Severity.LOW,
        "0": Severity.INFO,
        "informational": Severity.INFO,
        "info": Severity.INFO,
    }

    # Explicit Nmap state severity mapping
    NMAP_STATE_MAP: dict[str, Severity] = {
        "open": Severity.INFO,
        "filtered": Severity.INFO,
        "closed": Severity.INFO,
        "unfiltered": Severity.INFO,
    }

    @classmethod
    def map_zap_severity(cls, raw_severity: Any) -> tuple[Severity, str]:
        """Map raw OWASP ZAP risk descriptor to (Severity, original_string)."""
        if raw_severity is None:
            return Severity.INFO, "Unknown"

        raw_str = str(raw_severity).strip()
        # Clean 'Medium (High)' riskdesc format
        clean_key = raw_str.lower().split()[0].split("(")[0].strip()

        mapped = cls.ZAP_RISK_MAP.get(clean_key, Severity.INFO)
        return mapped, raw_str

    @classmethod
    def map_nmap_severity(cls, port_state: str) -> tuple[Severity, str]:
        """Map Nmap port state to informational severity.

        POLICY: An open port is a factual observation, not an inherent vulnerability.
        """
        raw_str = str(port_state).lower().strip()
        mapped = cls.NMAP_STATE_MAP.get(raw_str, Severity.INFO)
        return mapped, port_state

    @classmethod
    def map_generic_severity(cls, raw_severity: Any) -> tuple[Severity, str]:
        """Fallback mapper for generic scanner tools."""
        if raw_severity is None:
            return Severity.INFO, "Unknown"

        raw_str = str(raw_severity).upper().strip()
        if raw_str in Severity.__members__:
            return Severity[raw_str], raw_str

        # Substring heuristics for common scanner outputs
        lower_key = raw_str.lower()
        if "crit" in lower_key:
            return Severity.CRITICAL, raw_str
        if "high" in lower_key:
            return Severity.HIGH, raw_str
        if "med" in lower_key:
            return Severity.MEDIUM, raw_str
        if "low" in lower_key:
            return Severity.LOW, raw_str

        return Severity.INFO, raw_str
