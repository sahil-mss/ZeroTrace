from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from schemas.contracts import AIAnalysis, Assessment, Asset, Evidence, Finding
from schemas.enums import FindingSeverity, VerificationStatus


class ReportFindingEntry(BaseModel):
    finding_id: str
    title: str
    severity: FindingSeverity
    verification_status: VerificationStatus
    cwe: Optional[str]
    cve: Optional[str]
    description: str
    remediation: str
    evidence_ids: List[str]
    ai_summary: Optional[str] = None
    ai_reasoning: Optional[str] = None


class AssessmentReport(BaseModel):
    assessment_id: str
    assessment_name: str
    target: str
    scope_policy: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executive_summary: str
    severity_breakdown: Dict[str, int]
    total_assets: int
    total_findings: int
    verified_findings_count: int
    findings: List[ReportFindingEntry]
    remediation_roadmap: List[str]


class ReportGenerator:
    """
    Compiles normalized findings, asset footprints, and grounded AI triage into
    a verifiable, audit-ready security assessment report.
    """

    def generate(
        self,
        assessment: Assessment,
        assets: List[Asset],
        findings: List[Finding],
        evidence: List[Evidence],
        ai_analyses: Optional[Dict[str, AIAnalysis]] = None,
    ) -> AssessmentReport:
        ai_analyses = ai_analyses or {}

        # Severity breakdown
        counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        verified_count = sum(
            1 for f in findings if f.verification_status == VerificationStatus.CONFIRMED
        )

        # Executive summary synthesis
        critical_count = counts.get("critical", 0)
        high_count = counts.get("high", 0)

        exec_summary = (
            f"An authorized security assessment was conducted against {assessment.target} "
            f"under the '{assessment.name}' engagement. "
            f"A total of {len(findings)} findings were identified across {len(assets)} in-scope assets. "
            f"The assessment identified {critical_count} Critical-severity and {high_count} High-severity "
            f"issues. {verified_count} finding(s) have been empirically verified with captured evidence. "
            "Immediate remediation of high-severity authorization and injection vulnerabilities is strongly advised."
        )

        # Build entries
        entries: List[ReportFindingEntry] = []
        roadmap: List[str] = []

        for f in findings:
            analysis = ai_analyses.get(f.id)
            remediation_text = (
                (analysis.recommended_remediation if analysis else None)
                or f.remediation
                or "Review and apply vendor security patches and input validation."
            )

            entries.append(
                ReportFindingEntry(
                    finding_id=f.id,
                    title=f.title,
                    severity=f.severity,
                    verification_status=f.verification_status,
                    cwe=f.cwe,
                    cve=f.cve,
                    description=f.description,
                    remediation=remediation_text,
                    evidence_ids=f.evidence_references,
                    ai_summary=analysis.concise_summary if analysis else None,
                    ai_reasoning=analysis.reasoning_summary if analysis else None,
                )
            )

            # Prioritize roadmap based on severity
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                roadmap.append(f"[IMMEDIATE PRIORITY] {f.title}: {remediation_text.splitlines()[0]}")
            else:
                roadmap.append(f"[SCHEDULED DEFENSE] {f.title}: {remediation_text.splitlines()[0]}")

        return AssessmentReport(
            assessment_id=assessment.id,
            assessment_name=assessment.name,
            target=assessment.target,
            scope_policy="STRICT_BOUNDED_SCOPE",
            executive_summary=exec_summary,
            severity_breakdown=counts,
            total_assets=len(assets),
            total_findings=len(findings),
            verified_findings_count=verified_count,
            findings=entries,
            remediation_roadmap=roadmap,
        )
