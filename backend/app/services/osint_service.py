"""
OSINT Collection Service entry point for ZeroTrace services layer.
Re-exports the canonical implementation from modules.osint.service.
"""

from modules.osint.crtsh_adapter import CertificateTransparencyAdapter
from modules.osint.dns_adapter import DNSMetadataAdapter
from modules.osint.mock_adapter import MockOSINTAdapter
from modules.osint.service import OSINTCollectionService, OSINTCollectionSummary

__all__ = [
    "OSINTCollectionService",
    "OSINTCollectionSummary",
    "MockOSINTAdapter",
    "DNSMetadataAdapter",
    "CertificateTransparencyAdapter",
]
