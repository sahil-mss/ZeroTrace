"""
ZeroTrace Certificate Transparency (CT) OSINT Adapter.

Passive Certificate Transparency log adapter querying public CT logs (crt.sh)
with rate limiting, bounded response sizes, in-memory caching, graceful error handling,
and candidate-only asset attribution.
"""

import asyncio
import json
import logging
import time
from typing import Any

import httpx

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

logger = logging.getLogger("zerotrace.osint.ct")


class CertificateTransparencyAdapter(BaseOSINTAdapter):
    """
    Passive Certificate Transparency log intelligence adapter.
    Queries public CT logs (crt.sh) to discover issued certificates and subdomains.
    Disabled by default unless explicitly enabled in configuration.
    """

    adapter_name = "cert_transparency"
    adapter_version = "1.0.0"
    description = "Passive Certificate Transparency log adapter querying public CT logs with bounded resources"
    source_type = EvidenceSourceType.CERT_TRANSPARENCY
    supported_target_types = [TargetType.DOMAIN]
    is_passive = True
    required_permission = TestPermissionLevel.PASSIVE_ONLY

    def __init__(
        self,
        enabled: bool | None = None,
        http_client: httpx.AsyncClient | None = None,
        base_url: str = "https://crt.sh/",
        user_agent: str | None = None,
        timeout_seconds: float | None = None,
        max_response_bytes: int | None = None,
        rate_limit_per_minute: int | None = None,
        max_records: int | None = None,
    ):
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = bool(settings.OSINT_NETWORK_ENABLED and settings.OSINT_CT_ENABLED)

        self.base_url = base_url
        self.user_agent = user_agent or settings.OSINT_USER_AGENT
        timeout = timeout_seconds or settings.OSINT_REQUEST_TIMEOUT_SECONDS
        max_bytes = max_response_bytes or settings.OSINT_MAX_RESPONSE_BYTES
        rate_limit = rate_limit_per_minute or settings.OSINT_RATE_LIMIT_PER_MINUTE
        max_recs = max_records or settings.OSINT_MAX_RECORDS_PER_COLLECTION

        self.resource_budget = OSINTResourceBudget(
            timeout_seconds=timeout,
            max_response_bytes=max_bytes,
            rate_limit_per_minute=rate_limit,
            max_results_per_target=max_recs,
        )
        self._custom_client = http_client
        # In-memory query cache to avoid repeatedly querying the same source unnecessarily: {target: (timestamp, data)}
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._last_request_time: float = 0.0

    async def collect(self, target: str, context: OSINTCollectionContext) -> OSINTAdapterResult:
        start_time = time.monotonic()

        # 1. Configuration check (disabled by default)
        if not self.enabled:
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=[
                    "Certificate transparency adapter is disabled by default in configuration."
                ],
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

        # 4. Check In-Memory Query Cache (cache TTL: 300 seconds)
        now_ts = time.monotonic()
        raw_entries: list[dict[str, Any]] | None = None
        if target_clean in self._cache:
            cached_time, cached_data = self._cache[target_clean]
            if now_ts - cached_time < 300.0:
                raw_entries = cached_data

        # 5. If not cached, execute bounded HTTP query with rate limiting
        if raw_entries is None:
            # Enforce conservative per-source rate limits
            min_interval = 60.0 / max(1, self.resource_budget.rate_limit_per_minute)
            elapsed = now_ts - self._last_request_time
            if self._last_request_time > 0 and elapsed < min_interval:
                wait_time = min_interval - elapsed
                if wait_time > self.resource_budget.timeout_seconds:
                    return OSINTAdapterResult(
                        adapter_name=self.adapter_name,
                        adapter_version=self.adapter_version,
                        success=False,
                        observations=[],
                        errors=["Rate limit exceeded for certificate transparency adapter."],
                        execution_time_seconds=time.monotonic() - start_time,
                    )
                await asyncio.sleep(wait_time)

            self._last_request_time = time.monotonic()

            params = {"q": f"%.{target_clean}", "output": "json"}
            headers = {"User-Agent": self.user_agent, "Accept": "application/json"}

            try:
                if self._custom_client:
                    resp = await self._custom_client.get(
                        self.base_url,
                        params=params,
                        headers=headers,
                    )
                else:
                    async with httpx.AsyncClient(
                        timeout=self.resource_budget.timeout_seconds
                    ) as client:
                        resp = await client.get(
                            self.base_url,
                            params=params,
                            headers=headers,
                        )

                # Bounded response size check
                if len(resp.content) > self.resource_budget.max_response_bytes:
                    return OSINTAdapterResult(
                        adapter_name=self.adapter_name,
                        adapter_version=self.adapter_version,
                        success=False,
                        observations=[],
                        errors=[
                            f"Response size ({len(resp.content)} bytes) exceeded budget "
                            f"({self.resource_budget.max_response_bytes} bytes)."
                        ],
                        execution_time_seconds=time.monotonic() - start_time,
                    )

                if resp.status_code == 429:
                    return OSINTAdapterResult(
                        adapter_name=self.adapter_name,
                        adapter_version=self.adapter_version,
                        success=False,
                        observations=[],
                        errors=[
                            "Certificate transparency provider rate limit exceeded (HTTP 429)."
                        ],
                        execution_time_seconds=time.monotonic() - start_time,
                    )

                if resp.status_code != 200:
                    return OSINTAdapterResult(
                        adapter_name=self.adapter_name,
                        adapter_version=self.adapter_version,
                        success=False,
                        observations=[],
                        errors=[
                            f"Certificate transparency provider returned HTTP error {resp.status_code}."
                        ],
                        execution_time_seconds=time.monotonic() - start_time,
                    )

                try:
                    data = resp.json()
                    if not isinstance(data, list):
                        return OSINTAdapterResult(
                            adapter_name=self.adapter_name,
                            adapter_version=self.adapter_version,
                            success=False,
                            observations=[],
                            errors=[
                                "Malformed JSON structure from certificate transparency provider."
                            ],
                            execution_time_seconds=time.monotonic() - start_time,
                        )
                    raw_entries = data
                    self._cache[target_clean] = (time.monotonic(), raw_entries)
                except Exception as json_err:
                    return OSINTAdapterResult(
                        adapter_name=self.adapter_name,
                        adapter_version=self.adapter_version,
                        success=False,
                        observations=[],
                        errors=[
                            f"Failed to parse JSON from certificate transparency provider: {json_err}"
                        ],
                        execution_time_seconds=time.monotonic() - start_time,
                    )

            except httpx.TimeoutException:
                return OSINTAdapterResult(
                    adapter_name=self.adapter_name,
                    adapter_version=self.adapter_version,
                    success=False,
                    observations=[],
                    errors=["Certificate transparency query timed out."],
                    execution_time_seconds=time.monotonic() - start_time,
                )
            except Exception as net_err:
                return OSINTAdapterResult(
                    adapter_name=self.adapter_name,
                    adapter_version=self.adapter_version,
                    success=False,
                    observations=[],
                    errors=[
                        f"Network error contacting certificate transparency provider: {net_err}"
                    ],
                    execution_time_seconds=time.monotonic() - start_time,
                )

        now = utc_now()
        discovered_hostnames: set[str] = set()
        cert_metadata_list: list[dict[str, Any]] = []

        # 6. Parse certificates and hostnames (sanitizing personal info)
        for entry in raw_entries:
            name_val = entry.get("name_value", "")
            common_name = entry.get("common_name", "")

            # Filter metadata: do not store unrelated personal info
            sanitized_meta = {
                "id": entry.get("id"),
                "logged_at": entry.get("entry_timestamp"),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "issuer_name": entry.get("issuer_name"),
            }
            cert_metadata_list.append(sanitized_meta)

            all_names = f"{name_val}\n{common_name}".split("\n")
            for raw_name in all_names:
                cleaned = raw_name.strip().lower().lstrip("*.").rstrip(".")
                # Exclude IP addresses, emails, or non-domain strings
                if cleaned and "@" not in cleaned and " " not in cleaned and "." in cleaned:
                    discovered_hostnames.add(cleaned)

        sorted_hostnames = sorted(list(discovered_hostnames))[
            : self.resource_budget.max_results_per_target
        ]

        # 7. Construct observations
        # Primary CT log evidence observation
        primary_data = {
            "query_target": target_clean,
            "total_certificates_found": len(raw_entries),
            "discovered_hostnames_count": len(sorted_hostnames),
            "hostnames": sorted_hostnames,
            "source": "crt.sh",
        }

        observations: list[OSINTRawObservation] = [
            OSINTRawObservation(
                target=target_clean,
                target_type=TargetType.DOMAIN,
                confidence=1.0,
                data=primary_data,
                raw_payload=json.dumps(primary_data, sort_keys=True, default=str),
                sanitized_excerpt=(
                    f"Certificate transparency log query for '{target_clean}': "
                    f"{len(raw_entries)} certificate entries observed, {len(sorted_hostnames)} hostnames discovered."
                ),
                relationships={"discovered_candidates": sorted_hostnames},
                metadata={
                    "adapter": self.adapter_name,
                    "version": self.adapter_version,
                    "query_timestamp": now.isoformat(),
                    "is_candidate": False,
                    "active_scan_permitted": False,
                },
                collected_at=now,
            )
        ]

        # Discovered hostnames are initially marked as CANDIDATES:
        # "A hostname discovered in certificate data must never be scanned automatically.
        # Ensure any later active use requires a separate scope and permission check.
        # Do not infer that a certificate entry proves a service is live or that a host is in scope."
        for host in sorted_hostnames:
            if host == target_clean:
                continue
            is_sub = host.endswith(f".{target_clean}")
            obs = OSINTRawObservation(
                target=host,
                target_type=AssetType.SUBDOMAIN if is_sub else AssetType.DOMAIN,
                confidence=0.85,
                data={
                    "source": "cert_transparency",
                    "parent_domain": target_clean,
                    "is_candidate": True,
                    "service_live_confirmed": False,
                    "active_scan_permitted": False,
                },
                raw_payload=json.dumps({"target": host, "discovered_from": target_clean}),
                sanitized_excerpt=f"Discovered candidate hostname '{host}' in certificate transparency logs for '{target_clean}'",
                relationships={"discovered_from_domain": [target_clean]},
                metadata={
                    "is_candidate": True,
                    "service_live_confirmed": False,
                    "active_scan_permitted": False,
                    "discovered_via": "cert_transparency",
                },
                collected_at=now,
            )
            observations.append(obs)

        return OSINTAdapterResult(
            adapter_name=self.adapter_name,
            adapter_version=self.adapter_version,
            success=True,
            observations=observations,
            errors=[],
            execution_time_seconds=time.monotonic() - start_time,
        )


# Backward-compatible wrapper for legacy workflow
class CertTransparencyAdapter:
    """Legacy wrapper maintained for compatibility with workflow modules."""

    CRTSH_URL = "https://crt.sh/"

    def __init__(self, evidence_store: EvidenceStore, timeout_seconds: float = 10.0):
        self.evidence_store = evidence_store
        self.timeout = timeout_seconds

    async def query(self, assessment_id: str, target: str) -> dict[str, Any]:
        canon = ScopeValidator.canonicalize(target)
        domain = canon["hostname"]

        discovered_names: set[str] = set()
        raw_response_bytes = b""
        query_success = False
        error_msg = None

        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": "ZeroTrace-OSINT/1.0 (+https://github.com/sahil-mss/ZeroTrace)"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(self.CRTSH_URL, params=params, headers=headers)
                if resp.status_code == 200:
                    raw_response_bytes = resp.content
                    data = resp.json()
                    query_success = True
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            cleaned = sub.strip().lower()
                            if cleaned and not cleaned.startswith("*."):
                                discovered_names.add(cleaned)
                else:
                    error_msg = f"crt.sh returned HTTP {resp.status_code}"
        except httpx.TimeoutException:
            error_msg = "crt.sh query timed out"
        except Exception as e:
            error_msg = f"crt.sh query error: {str(e)}"

        evidence_data = {
            "query_domain": domain,
            "query_url": self.CRTSH_URL,
            "success": query_success,
            "error": error_msg,
            "discovered_count": len(discovered_names),
            "discovered_subdomains": sorted(list(discovered_names)),
        }

        evidence = self.evidence_store.create_evidence(
            assessment_id=assessment_id,
            source_type=EvidenceSourceType.CERT_TRANSPARENCY,
            tool_name="CertTransparencyAdapter",
            tool_version="1.0",
            data=evidence_data,
            raw_payload=raw_response_bytes if raw_response_bytes else None,
            metadata={"domain": domain, "subdomains_found": len(discovered_names)},
        )

        return {
            "domain": domain,
            "subdomains": sorted(list(discovered_names)),
            "evidence": evidence,
            "error": error_msg,
        }
