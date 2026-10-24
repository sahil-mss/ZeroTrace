import logging

from modules.ai.client import DeterministicGroundedProvider, LLMClient
from schemas.contracts import AIAnalysis, Evidence, Finding

logger = logging.getLogger(__name__)


class FindingAnalyst:
    """
    Analyzes raw security scanner findings and correlates them with empirical evidence.
    Enforces strict citation integrity to prevent hallucinations.
    """

    def __init__(self, client: LLMClient | None = None):
        self.client = client or DeterministicGroundedProvider()

    def analyze_finding(self, finding: Finding, evidence_records: list[Evidence]) -> AIAnalysis:
        """
        Produce a grounded AIAnalysis for a finding.
        Validates that all cited evidence IDs exist within the supplied evidence records.
        """
        available_ids: set[str] = {ev.id for ev in evidence_records}

        raw_analysis = self.client.generate_finding_analysis(finding, evidence_records)

        # Validate through Pydantic contract
        analysis = AIAnalysis.model_validate(raw_analysis)

        # Enforce Anti-Hallucination Guardrail
        analysis.validate_citations(available_ids)

        return analysis

    def batch_analyze(
        self, findings: list[Finding], evidence_records: list[Evidence]
    ) -> list[AIAnalysis]:
        """Analyze a collection of findings against available evidence records."""
        results: list[AIAnalysis] = []
        for finding in findings:
            # Filter evidence records relevant to this finding
            relevant_evidence = [
                ev for ev in evidence_records if ev.id in finding.evidence_references
            ]
            analysis = self.analyze_finding(finding, relevant_evidence)
            results.append(analysis)
        return results
