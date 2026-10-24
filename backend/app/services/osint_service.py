"""
OSINT Collection Service entry point for ZeroTrace services layer.
Re-exports the canonical implementation from modules.osint.service.
"""

from modules.osint.service import OSINTCollectionService, OSINTCollectionSummary

__all__ = [
    "OSINTCollectionService",
    "OSINTCollectionSummary",
]
