"""Deterministic Finding Deduplication Engine.

TASK 3: Computes stable finding fingerprints and aggregates duplicate vulnerability
observations without merging findings that refer to materially different assets.
"""

from datetime import datetime
import hashlib
from typing import Sequence

from aegispt.security_engine.schemas.finding import (
    EvidenceReference,
    NormalizedFinding,
)


class FindingDeduplicator:
    """Manages deterministic fingerprinting and aggregation of duplicate findings."""

    @classmethod
    def compute_fingerprint(cls, finding: NormalizedFinding) -> str:
        """Generate a deterministic SHA-256 fingerprint for a finding.

        Components considered:
        - Assessment ID (if present)
        - Asset identifier / target value (strictly separates distinct assets)
        - Vulnerability type (CWE ID or normalized title)
        - Affected parameter or URI path (from evidence metadata)
        - Scanner rule identifier (plugin ID / rule ID)
        """
        assessment_key = (finding.assessment_id or "default").strip()

        # Asset key: normalize target URL or IP
        target_val = (finding.target.target_value or "").strip().lower()
        asset_key = (finding.asset_id or target_val).strip()

        # Vulnerability type key
        if finding.cwe_id:
            vuln_type = f"CWE-{finding.cwe_id}"
        else:
            vuln_type = finding.title.strip().lower()

        # Parameter / URI path key
        param_key = ""
        rule_key = ""
        if finding.evidence:
            first_ev = finding.evidence[0]
            param_key = str(first_ev.metadata.get("parameter", "")).strip().lower()
            rule_key = str(first_ev.metadata.get("plugin_id", "")).strip().lower()

        fingerprint_source = f"{assessment_key}:{asset_key}:{target_val}:{vuln_type}:{param_key}:{rule_key}"
        return hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()

    @classmethod
    def generate_stable_id(cls, fingerprint: str) -> str:
        """Generate a stable, reproducible finding_id from its fingerprint."""
        return f"finding-{fingerprint[:16]}"

    @classmethod
    def deduplicate(
        cls,
        findings: Sequence[NormalizedFinding],
        assign_stable_ids: bool = True,
    ) -> list[NormalizedFinding]:
        """Aggregate duplicate findings into consolidated records.

        Rules:
        - Findings with identical fingerprints are merged.
        - Stable ID is assigned or preserved.
        - last_seen is updated to the latest observation timestamp.
        - New supporting evidence citations are appended without duplication.
        - Findings targeting distinct assets are NEVER merged.
        """
        deduped_map: dict[str, NormalizedFinding] = {}

        for finding in findings:
            fp = finding.fingerprint or cls.compute_fingerprint(finding)
            finding.fingerprint = fp

            if assign_stable_ids and not finding.finding_id.startswith("finding-"):
                finding.finding_id = cls.generate_stable_id(fp)

            if fp not in deduped_map:
                # First observation of this finding
                deduped_map[fp] = finding.model_copy(deep=True)
            else:
                # Duplicate observation: merge evidence and update last_seen
                cls._merge_duplicate(existing=deduped_map[fp], incoming=finding)

        return list(deduped_map.values())

    @classmethod
    def _merge_duplicate(
        cls,
        existing: NormalizedFinding,
        incoming: NormalizedFinding,
    ) -> None:
        """Merge incoming duplicate observation into the existing consolidated finding."""
        # Update last_seen to latest timestamp
        existing_ts = existing.last_seen or existing.first_observed_at
        incoming_ts = incoming.last_seen or incoming.first_observed_at
        if incoming_ts > existing_ts:
            existing.last_seen = incoming_ts

        # Aggregate evidence without duplicates
        existing_evidence_hashes = {
            e.sha256_hash or e.content_snippet for e in existing.evidence
        }

        for ev in incoming.evidence:
            ev_key = ev.sha256_hash or ev.content_snippet
            if ev_key not in existing_evidence_hashes:
                existing.evidence.append(ev)
                existing_evidence_hashes.add(ev_key)
                if ev.evidence_id not in existing.evidence_ids:
                    existing.evidence_ids.append(ev.evidence_id)
