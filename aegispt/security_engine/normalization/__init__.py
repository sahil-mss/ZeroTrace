"""Finding normalization subsystem for AegisPT.

Standardizes scanner outputs, maps severities, links raw evidence provenance,
and deduplicates findings deterministically.
"""

from aegispt.security_engine.normalization.deduplicator import FindingDeduplicator
from aegispt.security_engine.normalization.pipeline import NormalizationPipeline
from aegispt.security_engine.normalization.severity import SeverityMapper

__all__ = [
    "FindingDeduplicator",
    "NormalizationPipeline",
    "SeverityMapper",
]
