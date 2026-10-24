"""
ZeroTrace DNS Metadata OSINT Adapter.

Passive DNS metadata collection adapter querying limited record types (A, AAAA, CNAME, MX, NS)
using dnspython with bounded timeouts, error distinction, and strict scope validation.
"""

import json
import logging
import time
from typing import Any

import dns.exception
import dns.resolver

from aegis_common.enums import AssetType, EvidenceSourceType, TargetType, TestPermissionLevel
from aegis_common.utils import utc_now
from backend.app.core.config import settings
from backend.policy.scope_validator import ScopeValidator
from backend.storage.evidence_store import EvidenceStore
from modules.osint.contracts import (
    BaseOSINTAdapter,
    OSINTAdapterResult,
    OSINTCollectionContext,
    OSINTRawObservation,
    OSINTResourceBudget,
)

logger = logging.getLogger("zerotrace.osint.dns")

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS"]


class DNSMetadataAdapter(BaseOSINTAdapter):
    """
    Passive DNS metadata collection adapter.
    Queries A, AAAA, CNAME, MX, and NS records for an explicitly approved domain.
    Disabled by default unless explicitly enabled in configuration.
    """

    adapter_name = "dns_metadata"
    adapter_version = "1.0.0"
    description = (
        "Passive DNS metadata collection adapter querying A, AAAA, CNAME, MX, and NS records"
    )
    source_type = EvidenceSourceType.DNS_LOOKUP
    supported_target_types = [TargetType.DOMAIN]
    is_passive = True
    required_permission = TestPermissionLevel.PASSIVE_ONLY

    def __init__(
        self,
        enabled: bool | None = None,
        resolver: Any | None = None,
        timeout_seconds: float | None = None,
        max_records: int | None = None,
    ):
        # Disabled by default unless explicitly enabled in configuration or constructor
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = bool(settings.OSINT_NETWORK_ENABLED and settings.OSINT_DNS_ENABLED)

        timeout = timeout_seconds or settings.OSINT_REQUEST_TIMEOUT_SECONDS
        max_recs = max_records or settings.OSINT_MAX_RECORDS_PER_COLLECTION
        self.resource_budget = OSINTResourceBudget(
            timeout_seconds=timeout,
            max_results_per_target=max_recs,
            rate_limit_per_minute=settings.OSINT_RATE_LIMIT_PER_MINUTE,
        )
        self._custom_resolver = resolver

    async def collect(self, target: str, context: OSINTCollectionContext) -> OSINTAdapterResult:
        start_time = time.monotonic()

        # 1. Configuration check (disabled by default)
        if not self.enabled:
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=["DNS metadata adapter is disabled by default in configuration."],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 2. Cooperative cancellation check
        if context.cancellation_token.is_cancelled:
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=[f"Cancelled before collection: {context.cancellation_token.reason}"],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 3. Canonicalize and validate target scope
        target_clean = target.strip().lower().rstrip(".")
        approved_clean = [t.strip().lower().rstrip(".") for t in context.approved_targets]
        if target_clean not in approved_clean:
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=[
                    f"Target '{target}' is not in approved assessment targets: {approved_clean}"
                ],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 4. Initialize DNS Resolver with explicit lifetime and timeouts
        resolver = self._custom_resolver or dns.resolver.Resolver()
        if hasattr(resolver, "lifetime"):
            resolver.lifetime = self.resource_budget.timeout_seconds
        if hasattr(resolver, "timeout"):
            resolver.timeout = self.resource_budget.timeout_seconds

        records_by_type: dict[str, list[str]] = {}
        query_outcomes: dict[str, dict[str, Any]] = {}
        relationships: dict[str, list[str]] = {
            "resolves_to_ip": [],
            "canonical_name": [],
            "mail_exchanger": [],
            "nameserver": [],
        }

        total_records_count = 0
        now = utc_now()

        # 5. Query limited, safe record types (no zone transfers, no brute force)
        for rtype in RECORD_TYPES:
            if context.cancellation_token.is_cancelled:
                return OSINTAdapterResult(
                    adapter_name=self.adapter_name,
                    adapter_version=self.adapter_version,
                    success=False,
                    observations=[],
                    errors=[f"Cancelled during DNS query: {context.cancellation_token.reason}"],
                    execution_time_seconds=time.monotonic() - start_time,
                )

            records_by_type[rtype] = []
            try:
                answers = resolver.resolve(target_clean, rtype)
                for rdata in answers:
                    if total_records_count >= self.resource_budget.max_results_per_target:
                        break
                    val = str(rdata).strip('"').rstrip(".")
                    records_by_type[rtype].append(val)
                    total_records_count += 1

                    # Categorize relationships
                    if rtype in ("A", "AAAA"):
                        relationships["resolves_to_ip"].append(val)
                    elif rtype == "CNAME":
                        relationships["canonical_name"].append(val.lower())
                    elif rtype == "MX":
                        # MX records typically format as "10 mail.example.com"
                        parts = val.split()
                        mx_host = parts[-1].lower() if parts else val.lower()
                        relationships["mail_exchanger"].append(mx_host)
                    elif rtype == "NS":
                        relationships["nameserver"].append(val.lower())

                query_outcomes[rtype] = {
                    "status": "RESOLVED",
                    "count": len(records_by_type[rtype]),
                }

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Distinguish missing records from resolver failures
                query_outcomes[rtype] = {
                    "status": "NO_RECORD",
                    "count": 0,
                    "detail": "Record type not present for domain",
                }
            except dns.exception.Timeout:
                query_outcomes[rtype] = {
                    "status": "RESOLVER_FAILURE",
                    "count": 0,
                    "error": "Query timed out against DNS nameserver",
                }
            except Exception as e:
                query_outcomes[rtype] = {
                    "status": "RESOLVER_FAILURE",
                    "count": 0,
                    "error": str(e),
                }

        # Deduplicate relationship targets
        for key in relationships:
            relationships[key] = sorted(list(set(relationships[key])))

        # 6. Build structured observation
        data = {
            "target": target_clean,
            "query_type": "DNS_METADATA_PASSIVE",
            "records": records_by_type,
            "query_outcomes": query_outcomes,
            "source": "dns_resolver",
            "total_records_found": total_records_count,
        }

        observation = OSINTRawObservation(
            target=target_clean,
            target_type=TargetType.DOMAIN,
            confidence=1.0,
            data=data,
            raw_payload=json.dumps(data, sort_keys=True, default=str),
            sanitized_excerpt=(
                f"DNS metadata for '{target_clean}': {total_records_count} records resolved across "
                f"{len(RECORD_TYPES)} standard query types."
            ),
            relationships=relationships,
            metadata={
                "adapter": self.adapter_name,
                "version": self.adapter_version,
                "query_timestamp": now.isoformat(),
                "is_candidate": False,
                "active_scan_permitted": False,
            },
            collected_at=now,
        )

        observations = [observation]

        # Candidate assets: CNAME or MX hosts are candidate subdomains / domains
        for cname in relationships["canonical_name"]:
            observations.append(
                OSINTRawObservation(
                    target=cname,
                    target_type=AssetType.DOMAIN,
                    confidence=0.9,
                    data={
                        "source": "cname_reference",
                        "parent": target_clean,
                        "is_candidate": True,
                    },
                    raw_payload=json.dumps({"target": cname, "parent": target_clean}),
                    sanitized_excerpt=f"Candidate canonical hostname {cname} from DNS CNAME record of {target_clean}",
                    relationships={"canonical_for": [target_clean]},
                    metadata={
                        "is_candidate": True,
                        "active_scan_permitted": False,
                        "discovered_via": "dns_cname",
                    },
                    collected_at=now,
                )
            )

        return OSINTAdapterResult(
            adapter_name=self.adapter_name,
            adapter_version=self.adapter_version,
            success=True,
            observations=observations,
            errors=[],
            execution_time_seconds=time.monotonic() - start_time,
        )


# Backward-compatible wrapper for legacy workflow
class DnsLookupAdapter:
    """Legacy wrapper maintained for compatibility with workflow modules."""

    def __init__(self, evidence_store: EvidenceStore, timeout_seconds: float = 5.0):
        self.evidence_store = evidence_store
        self.timeout = timeout_seconds

    def query(self, assessment_id: str, target: str) -> dict[str, Any]:
        canon = ScopeValidator.canonicalize(target)
        hostname = canon["hostname"]

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        records: dict[str, list[str]] = {rtype: [] for rtype in RECORD_TYPES}
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(hostname, rtype)
                for rdata in answers:
                    records[rtype].append(str(rdata).strip('"'))
            except Exception:
                continue

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
