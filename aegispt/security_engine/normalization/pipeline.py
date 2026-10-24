"""Normalization Pipeline Service.

TASK 1: Core normalization service converting scanner-specific outputs into
validated, deduplicated, and evidence-linked AegisPT Finding models.
"""

from aegispt.security_engine.normalization.deduplicator import FindingDeduplicator
from aegispt.security_engine.normalization.severity import SeverityMapper
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.schemas.result import ScanResult


class NormalizationPipeline:
    """Orchestrates validation, severity mapping, asset association, and deduplication."""

    @classmethod
    def normalize_scan_result(
        cls,
        result: ScanResult,
        assessment_id: str | None = None,
        tool_version: str | None = None,
    ) -> list[NormalizedFinding]:
        """Normalize findings from a completed ScanResult instance."""
        if not isinstance(result, ScanResult):
            raise TypeError(f"Expected ScanResult instance, got {type(result).__name__}")

        scanner_id = result.scanner_id.lower().strip()
        raw_findings = result.findings

        # If Nmap scanner, enforce policy: factual open ports are observations, not vulnerabilities
        if scanner_id == "nmap" and not raw_findings:
            return []

        normalized: list[NormalizedFinding] = []

        for item in raw_findings:
            processed = cls.normalize_finding(
                finding=item,
                scanner_id=scanner_id,
                assessment_id=assessment_id,
                tool_version=tool_version,
                raw_artifact_id=result.raw_evidence.artifact_id if result.raw_evidence else None,
                raw_sha256=result.raw_evidence.sha256_hash if result.raw_evidence else None,
            )
            normalized.append(processed)

        # Deduplicate and assign stable reproducible IDs
        return FindingDeduplicator.deduplicate(normalized)

    @classmethod
    def normalize_finding(
        cls,
        finding: NormalizedFinding,
        scanner_id: str | None = None,
        assessment_id: str | None = None,
        tool_version: str | None = None,
        raw_artifact_id: str | None = None,
        raw_sha256: str | None = None,
    ) -> NormalizedFinding:
        """Process and validate an individual NormalizedFinding instance."""
        target_scanner = (scanner_id or finding.scanner_id).lower().strip()

        # Severity normalization & original severity preservation
        original_severity = finding.original_severity or str(finding.severity)
        if target_scanner == "owasp_zap":
            mapped_sev, orig_str = SeverityMapper.map_zap_severity(original_severity)
        else:
            mapped_sev, orig_str = SeverityMapper.map_generic_severity(original_severity)

        # Link supporting evidence with raw artifact provenance if missing
        if raw_artifact_id or raw_sha256:
            for ev in finding.evidence:
                if not ev.source_artifact_id and raw_artifact_id:
                    ev.source_artifact_id = raw_artifact_id
                if not ev.sha256_hash and raw_sha256:
                    ev.sha256_hash = raw_sha256

        # Build updated finding model
        finding_data = finding.model_dump()
        finding_data["severity"] = mapped_sev
        finding_data["original_severity"] = orig_str
        if assessment_id:
            finding_data["assessment_id"] = assessment_id
        if tool_version:
            finding_data["tool_version"] = tool_version

        # Compute deterministic fingerprint
        temp_finding = NormalizedFinding.model_validate(finding_data)
        fp = FindingDeduplicator.compute_fingerprint(temp_finding)
        temp_finding.fingerprint = fp
        temp_finding.finding_id = FindingDeduplicator.generate_stable_id(fp)

        return temp_finding
