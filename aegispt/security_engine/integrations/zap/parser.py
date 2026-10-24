"""OWASP ZAP Alert Parser and Normalization Engine.

TASK 4 & 5: Extracts structured alert telemetry from OWASP ZAP (API JSON
responses or Automation Framework reports) and maps them into the common
NormalizedFinding schema.

CRITICAL POLICY:
- All generated findings start with verified=False (UNVERIFIED status).
- Original alert attributes (parameter, attack payload, confidence, plugin ID)
  are preserved verbatim in EvidenceReference and metadata.
"""

import json
from pathlib import Path
from typing import Any

from aegispt.security_engine.schemas.enums import AssetType, Severity
from aegispt.security_engine.schemas.finding import (
    EvidenceReference,
    NormalizedFinding,
)
from aegispt.security_engine.schemas.target import ScanTarget


class ZAPParserError(Exception):
    """Raised when ZAP alert output is malformed, truncated, or invalid JSON."""


class ZAPAlertParser:
    """Parses raw OWASP ZAP alert JSON into normalized security findings."""

    SCANNER_ID = "owasp_zap"

    # Mapping from ZAP risk string or code to platform Severity enum
    RISK_MAP = {
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

    @classmethod
    def parse_file(
        cls,
        file_path: str | Path,
        source_artifact_id: str | None = None,
        source_sha256: str | None = None,
        strict: bool = True,
    ) -> list[NormalizedFinding]:
        """Parse ZAP alerts from a JSON file path."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"ZAP report file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            return cls.parse_string(
                content,
                source_artifact_id=source_artifact_id,
                source_sha256=source_sha256,
                strict=strict,
            )
        except Exception as exc:
            if isinstance(exc, (FileNotFoundError, ZAPParserError)):
                raise
            raise ZAPParserError(f"Failed to read ZAP report file '{path}': {exc}") from exc

    @classmethod
    def parse_string(
        cls,
        json_text: str,
        source_artifact_id: str | None = None,
        source_sha256: str | None = None,
        strict: bool = True,
    ) -> list[NormalizedFinding]:
        """Parse ZAP alerts from a JSON string."""
        if not json_text or not json_text.strip():
            if strict:
                raise ZAPParserError("ZAP JSON document is empty.")
            return []

        try:
            data = json.loads(json_text)
        except json.JSONDecodeError as exc:
            if strict:
                raise ZAPParserError(f"Malformed ZAP JSON document: {exc}") from exc
            return []

        raw_alerts = cls._extract_raw_alert_nodes(data)
        findings: list[NormalizedFinding] = []

        for item in raw_alerts:
            if not isinstance(item, dict):
                continue
            finding = cls._normalize_single_alert(
                item,
                source_artifact_id=source_artifact_id,
                source_sha256=source_sha256,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    @classmethod
    def _extract_raw_alert_nodes(cls, data: Any) -> list[dict[str, Any]]:
        """Normalize different ZAP JSON layouts (API flat lists vs Automation Framework)."""
        if isinstance(data, list):
            # Direct alert list: [{"alert": "...", ...}]
            return [x for x in data if isinstance(x, dict)]

        if isinstance(data, dict):
            # Format 1: API response {"alerts": [...]}
            if "alerts" in data and isinstance(data["alerts"], list):
                return [x for x in data["alerts"] if isinstance(x, dict)]

            # Format 2: Automation Framework {"site": [{"alerts": [...]}]}
            if "site" in data and isinstance(data["site"], list):
                collected: list[dict[str, Any]] = []
                for site_node in data["site"]:
                    if isinstance(site_node, dict) and "alerts" in site_node:
                        site_alerts = site_node["alerts"]
                        if isinstance(site_alerts, list):
                            collected.extend([x for x in site_alerts if isinstance(x, dict)])
                return collected

            # Format 3: Single alert dict {"alert": "...", "risk": "..."}
            if "alert" in data or "name" in data or "pluginId" in data:
                return [data]

        return []

    @classmethod
    def _normalize_single_alert(
        cls,
        node: dict[str, Any],
        source_artifact_id: str | None = None,
        source_sha256: str | None = None,
    ) -> NormalizedFinding | None:
        """Convert a single ZAP alert dictionary into a NormalizedFinding."""
        title = node.get("name") or node.get("alert")
        if not title:
            # Unidentified alert without title or name
            return None

        # Severity resolution
        raw_risk = str(node.get("risk") or node.get("riskdesc") or node.get("riskcode") or "0").lower().strip()
        # Handle 'medium (high)' format from riskdesc
        clean_risk = raw_risk.split()[0].split("(")[0].strip()
        severity = cls.RISK_MAP.get(clean_risk, Severity.INFO)

        description = node.get("description") or node.get("desc") or "No description provided."

        # Affected URL & parameter resolution
        affected_url = node.get("url") or node.get("uri")
        param = node.get("param") or ""
        evidence_snippet = node.get("evidence") or node.get("attack") or ""

        # Check nested instances from Automation Framework format
        if not affected_url and "instances" in node and isinstance(node["instances"], list):
            instances = node["instances"]
            if instances and isinstance(instances[0], dict):
                first_inst = instances[0]
                affected_url = first_inst.get("uri")
                if not param:
                    param = first_inst.get("param") or ""
                if not evidence_snippet:
                    evidence_snippet = first_inst.get("evidence") or first_inst.get("attack") or ""

        affected_url = affected_url or "http://127.0.0.1:3000/"

        # Target model
        target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value=affected_url,
        )

        # CWE ID extraction
        raw_cwe = node.get("cweid") or node.get("cwe_id")
        cwe_id: int | None = None
        if raw_cwe is not None:
            try:
                cwe_id = int(str(raw_cwe).strip())
            except ValueError:
                cwe_id = None

        # Evidence references
        confidence = str(node.get("confidence") or "Unknown")
        alert_id = str(node.get("pluginId") or node.get("pluginid") or node.get("id") or node.get("alertRef") or "")

        evidence = [
            EvidenceReference(
                evidence_type="zap_alert_instance",
                content_snippet=evidence_snippet or f"Alert triggered on parameter: '{param or '<none>'}'",
                source_artifact_id=source_artifact_id,
                sha256_hash=source_sha256,
                metadata={
                    "plugin_id": alert_id,
                    "confidence": confidence,
                    "parameter": param,
                    "attack": node.get("attack", ""),
                    "wasc_id": node.get("wascid", ""),
                    "reference": node.get("reference", ""),
                },
            )
        ]

        remediation = node.get("solution")

        # TASK 5 POLICY: "Use UNVERIFIED as the initial verification status unless independent verification already exists."
        return NormalizedFinding(
            scanner_id=cls.SCANNER_ID,
            title=title.strip(),
            description=description.strip(),
            severity=severity,
            target=target,
            cwe_id=cwe_id,
            evidence=evidence,
            remediation=remediation.strip() if remediation else None,
            verified=False,  # Strictly unverified initially
        )
