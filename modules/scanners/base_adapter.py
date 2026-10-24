from abc import ABC, abstractmethod
from typing import Any

from schemas.models import Assessment, Job


class BaseScannerAdapter(ABC):
    """
    Standard interface for all Person 2 security tool adapters (Nmap, ZAP, Nuclei).
    Every scanner adapter must adhere to this contract.
    """

    def __init__(self, tool_name: str, tool_version: str = "1.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    @abstractmethod
    def validate_preconditions(self, job: Job, assessment: Assessment) -> bool:
        """Verifies target scope and resource parameters before tool invocation."""
        pass

    @abstractmethod
    async def run_scan(self, job: Job, assessment: Assessment) -> dict[str, Any]:
        """
        Executes bounded scan profile, parses structured output,
        creates Evidence and normalized Finding records.
        """
        pass
