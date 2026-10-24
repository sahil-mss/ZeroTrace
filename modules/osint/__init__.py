"""
ZeroTrace OSINT Package.

Modular passive intelligence collection framework with pluggable source adapters,
deterministic scope validation, bounded execution, and immutable evidence storage.
"""

from modules.osint.contracts import (
    BaseOSINTAdapter,
    CancellationToken,
    OSINTAdapterResult,
    OSINTCollectionContext,
    OSINTRawObservation,
    OSINTResourceBudget,
)
from modules.osint.crtsh_adapter import CertificateTransparencyAdapter
from modules.osint.dns_adapter import DNSMetadataAdapter
from modules.osint.mock_adapter import MockOSINTAdapter
from modules.osint.service import OSINTCollectionService, OSINTCollectionSummary

__all__ = [
    "BaseOSINTAdapter",
    "CancellationToken",
    "OSINTCollectionContext",
    "OSINTRawObservation",
    "OSINTAdapterResult",
    "OSINTResourceBudget",
    "MockOSINTAdapter",
    "DNSMetadataAdapter",
    "CertificateTransparencyAdapter",
    "OSINTCollectionService",
    "OSINTCollectionSummary",
]
