import socket
from typing import Any

import dns.resolver

from backend.policy.scope_validator import ScopeValidator
from backend.storage.evidence_store import EvidenceStore
from schemas.enums import EvidenceSourceType


class DnsLookupAdapter:
    """
    Passive DNS Intelligence Adapter.
    Performs standard DNS record enumeration (A, AAAA, CNAME, MX, TXT, NS).
    Produces cryptographic Evidence records.
    """

    def __init__(self, evidence_store: EvidenceStore, timeout_seconds: float = 5.0):
        self.evidence_store = evidence_store
        self.timeout = timeout_seconds

    def query(self, assessment_id: str, target: str) -> dict[str, Any]:
        """
        Executes safe, standard DNS lookups for canonical host.
        Returns a dict containing observed records and generated Evidence.
        """
        canon = ScopeValidator.canonicalize(target)
        hostname = canon["hostname"]

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        records: dict[str, list[str]] = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "TXT": [],
            "NS": [],
        }

        # 1. Standard DNS record queries
        for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]:
            try:
                answers = resolver.resolve(hostname, rtype)
                for rdata in answers:
                    records[rtype].append(str(rdata).strip('"'))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception:
                continue

        # Fallback to standard socket gethostbyname if dnspython yields no A records (e.g. local /etc/hosts or lab target)
        if not records["A"]:
            try:
                ip = socket.gethostbyname(hostname)
                if ip:
                    records["A"].append(ip)
            except Exception:
                pass

        # 2. Package observation into verifiable Evidence
        evidence_payload = {
            "target": hostname,
            "query_type": "DNS_PASSIVE_ENUMERATION",
            "records": records,
        }

        evidence = self.evidence_store.create_evidence(
            assessment_id=assessment_id,
            source_type=EvidenceSourceType.DNS_LOOKUP,
            tool_name="DnsLookupAdapter",
            tool_version="1.0",
            data=evidence_payload,
            metadata={"hostname": hostname, "total_records": sum(len(v) for v in records.values())},
        )

        return {
            "hostname": hostname,
            "records": records,
            "evidence": evidence,
        }
