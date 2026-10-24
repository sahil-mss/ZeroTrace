import logging
from typing import List, Optional

from modules.ai.adapter import BaseModelAdapter, DeterministicFallbackAdapter, RemoteLLMAdapter
from modules.ai.config import AIConfig
from schemas.contracts import AIAnalysis, Evidence, Finding

logger = logging.getLogger(__name__)


class AIAnalysisService:
    """
    Central service for executing finding triage and analysis.
    Manages adapter selection, config ingestion, and fallback reliability.
    """

    def __init__(self, config: Optional[AIConfig] = None, adapter: Optional[BaseModelAdapter] = None):
        self.config = config or AIConfig()
        if adapter:
            self.adapter = adapter
        elif self.config.provider == "deterministic":
            self.adapter = DeterministicFallbackAdapter()
        else:
            self.adapter = RemoteLLMAdapter(config=self.config)

    def analyze_finding(self, finding: Finding, evidence_records: List[Evidence]) -> AIAnalysis:
        """
        Analyze a finding against its available evidence records.
        Guarantees validated, structured, safe output.
        """
        return self.adapter.analyze(finding, evidence_records)
