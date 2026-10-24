"""Finding Verification Engine.

TASK 1 & 6: Orchestrates deterministic verification rules, plugin dispatching,
and immutable audit log recording.
"""

from datetime import datetime, timezone
from typing import Any, Sequence
import requests

from aegispt.security_engine.schemas.enums import VerificationStatus
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.verification.base import BaseVerifier
from aegispt.security_engine.verification.models import VerificationRecord
from aegispt.security_engine.verification.plugins import (
    HeaderSecurityVerifier,
    LabGroundTruthVerifier,
    PassiveReflectionVerifier,
)


class VerificationEngine:
    """Core verification service validating scanner findings against evidence and safety rules."""

    def __init__(
        self,
        verifiers: list[BaseVerifier] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.verifiers: list[BaseVerifier] = verifiers or [
            HeaderSecurityVerifier(),
            PassiveReflectionVerifier(),
            LabGroundTruthVerifier(),
        ]
        self._session = session or requests.Session()
        self._audit_log: list[VerificationRecord] = []

    @property
    def audit_log(self) -> list[VerificationRecord]:
        """Return immutable history of verification decisions."""
        return list(self._audit_log)

    def verify_finding(
        self,
        finding: NormalizedFinding,
        assessment_scope: set[str] | None = None,
    ) -> tuple[NormalizedFinding, VerificationRecord]:
        """Execute deterministic verification pipeline on a single finding."""
        prev_status = str(finding.verification_status)
        finding_id = finding.finding_id
        evidence_ids = list(finding.evidence_ids)

        # -------------------------------------------------------------
        # STEP 1: Confirm affected asset belongs to assessment scope
        # -------------------------------------------------------------
        if assessment_scope is not None:
            target_val = (finding.target.target_value or "").strip().lower()
            asset_id = (finding.asset_id or "").strip()
            # Normalize scope entries to lower case
            normalized_scope = {s.strip().lower() for s in assessment_scope}

            # Check if either target_value or asset_id is in assessment_scope
            in_scope = (
                target_val in normalized_scope
                or asset_id.lower() in normalized_scope
                or any(target_val.startswith(s) for s in normalized_scope)
            )

            if not in_scope:
                record = self._record_decision(
                    finding_id=finding_id,
                    method="rule_assessment_scope_check",
                    evidence_ids=evidence_ids,
                    prev_status=prev_status,
                    new_status=VerificationStatus.UNVERIFIED,
                    reason=f"Target asset '{target_val}' does not belong to authorized assessment scope.",
                )
                self._update_finding_status(finding, VerificationStatus.UNVERIFIED)
                return finding, record

        # -------------------------------------------------------------
        # STEP 2: Confirm supporting evidence exists
        # -------------------------------------------------------------
        if not finding.evidence or not any(e.content_snippet.strip() for e in finding.evidence):
            record = self._record_decision(
                finding_id=finding_id,
                method="rule_evidence_existence_check",
                evidence_ids=evidence_ids,
                prev_status=prev_status,
                new_status=VerificationStatus.UNVERIFIED,
                reason="Finding rejected: No verifiable supporting evidence citations provided.",
            )
            self._update_finding_status(finding, VerificationStatus.UNVERIFIED)
            return finding, record

        # -------------------------------------------------------------
        # STEP 3: Confirm evidence references the correct asset
        # -------------------------------------------------------------
        first_ev = finding.evidence[0]
        ev_target = first_ev.metadata.get("target_url") or first_ev.metadata.get("uri")
        if ev_target:
            ev_target_str = str(ev_target).strip().lower()
            finding_target_str = finding.target.target_value.strip().lower()
            if not (ev_target_str in finding_target_str or finding_target_str in ev_target_str):
                record = self._record_decision(
                    finding_id=finding_id,
                    method="rule_evidence_asset_correlation",
                    evidence_ids=evidence_ids,
                    prev_status=prev_status,
                    new_status=VerificationStatus.UNVERIFIED,
                    reason=(
                        f"Evidence citation references mismatched target '{ev_target_str}', "
                        f"which does not match finding target '{finding_target_str}'."
                    ),
                )
                self._update_finding_status(finding, VerificationStatus.UNVERIFIED)
                return finding, record

        # -------------------------------------------------------------
        # STEP 4: Check whether scanner result is structurally valid
        # -------------------------------------------------------------
        if not finding.title or not finding.scanner_id or not finding.target.target_value:
            record = self._record_decision(
                finding_id=finding_id,
                method="rule_structural_validity_check",
                evidence_ids=evidence_ids,
                prev_status=prev_status,
                new_status=VerificationStatus.UNVERIFIED,
                reason="Finding is structurally invalid (missing required title, scanner_id, or target).",
            )
            self._update_finding_status(finding, VerificationStatus.UNVERIFIED)
            return finding, record

        # -------------------------------------------------------------
        # STEP 5 & 6: Execute modular verifier plugins (reproducible check)
        # -------------------------------------------------------------
        cwe_key = f"CWE-{finding.cwe_id}" if finding.cwe_id else None
        verdict = VerificationStatus.NEEDS_REVIEW
        decision_reason = "No specialized verifier matched; requires manual human review."
        method_used = "default_fallback_review"
        decision_meta: dict[str, Any] = {}

        for verifier in self.verifiers:
            # Match by CWE or general supported types
            if cwe_key and cwe_key in verifier.supported_finding_types:
                try:
                    verdict, decision_reason, decision_meta = verifier.verify(
                        finding=finding,
                        session=self._session,
                    )
                    method_used = verifier.verification_id
                    break
                except Exception as exc:
                    verdict = VerificationStatus.NEEDS_REVIEW
                    decision_reason = f"Verification plugin '{verifier.verification_id}' encountered error: {exc}"
                    method_used = verifier.verification_id
                    decision_meta = {"error": str(exc)}
                    break

        # If no specific CWE plugin matched, check if ground truth verifier can inspect
        if method_used == "default_fallback_review":
            gt_verifier = next((v for v in self.verifiers if isinstance(v, LabGroundTruthVerifier)), None)
            if gt_verifier:
                try:
                    verdict, decision_reason, decision_meta = gt_verifier.verify(finding, session=self._session)
                    method_used = gt_verifier.verification_id
                except Exception as exc:
                    verdict = VerificationStatus.NEEDS_REVIEW
                    decision_reason = f"Ground truth verifier failed: {exc}"
                    method_used = "verifier_lab_ground_truth"

        # -------------------------------------------------------------
        # STEP 7: Record audit entry and update finding
        # -------------------------------------------------------------
        record = self._record_decision(
            finding_id=finding_id,
            method=method_used,
            evidence_ids=evidence_ids,
            prev_status=prev_status,
            new_status=verdict,
            reason=decision_reason,
            metadata=decision_meta,
        )
        self._update_finding_status(finding, verdict)
        return finding, record

    def verify_all(
        self,
        findings: Sequence[NormalizedFinding],
        assessment_scope: set[str] | None = None,
    ) -> tuple[list[NormalizedFinding], list[VerificationRecord]]:
        """Run verification across a collection of findings."""
        updated_findings: list[NormalizedFinding] = []
        records: list[VerificationRecord] = []

        for finding in findings:
            updated, record = self.verify_finding(finding, assessment_scope=assessment_scope)
            updated_findings.append(updated)
            records.append(record)

        return updated_findings, records

    def _record_decision(
        self,
        finding_id: str,
        method: str,
        evidence_ids: list[str],
        prev_status: str,
        new_status: VerificationStatus,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> VerificationRecord:
        """Create and append an immutable audit log entry."""
        record = VerificationRecord(
            finding_id=finding_id,
            verification_method=method,
            timestamp=datetime.now(timezone.utc),
            evidence_ids=evidence_ids,
            previous_status=prev_status,
            new_status=new_status,
            reason=reason,
            metadata=metadata or {},
        )
        self._audit_log.append(record)
        return record

    @staticmethod
    def _update_finding_status(
        finding: NormalizedFinding,
        new_status: VerificationStatus,
    ) -> None:
        """Update finding's verification status and boolean flag."""
        finding.verification_status = new_status.value
        finding.verified = (new_status == VerificationStatus.CONFIRMED)
