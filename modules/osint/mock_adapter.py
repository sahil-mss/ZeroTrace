"""
Deterministic Mock OSINT Adapter for ZeroTrace / AegisPT.

Returns reproducible synthetic observations for testing the end-to-end pipeline
without external network access or live target interaction.
"""

import asyncio
import json
import time
from datetime import UTC, datetime

from aegis_common.enums import AssetType, EvidenceSourceType, TargetType, TestPermissionLevel
from modules.osint.contracts import (
    BaseOSINTAdapter,
    OSINTAdapterResult,
    OSINTCollectionContext,
    OSINTRawObservation,
    OSINTResourceBudget,
)


class MockOSINTAdapter(BaseOSINTAdapter):
    """
    Deterministic Mock OSINT Adapter.
    Generates synthetic DNS records, subdomains, and related IPs for testing.
    """

    adapter_name = "mock_osint"
    adapter_version = "1.0.0"
    description = "Deterministic synthetic OSINT adapter for offline testing and verification"
    source_type = EvidenceSourceType.DNS_LOOKUP
    supported_target_types = [TargetType.DOMAIN, TargetType.URL]
    is_passive = True
    required_permission = TestPermissionLevel.PASSIVE_ONLY
    resource_budget = OSINTResourceBudget(timeout_seconds=5.0, max_results_per_target=50)
    enabled = True

    def __init__(
        self,
        simulate_timeout: bool = False,
        simulate_error: bool = False,
        simulate_malformed: bool = False,
    ):
        self.simulate_timeout = simulate_timeout
        self.simulate_error = simulate_error
        self.simulate_malformed = simulate_malformed

    async def collect(self, target: str, context: OSINTCollectionContext) -> OSINTAdapterResult:
        start_time = time.monotonic()

        # 1. Cooperative cancellation check before work
        if context.cancellation_token.is_cancelled:
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=[f"Cancelled before collection: {context.cancellation_token.reason}"],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 2. Simulate timeout if requested
        if self.simulate_timeout or "timeout" in target.lower():
            # Wait longer than typical adapter budget or simulate sleep
            await asyncio.sleep(self.resource_budget.timeout_seconds + 0.5)

        # 3. Simulate failure if requested
        if self.simulate_error or "error" in target.lower():
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=[f"Simulated adapter failure for target: {target}"],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 4. Check cancellation again
        if context.cancellation_token.is_cancelled:
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=False,
                observations=[],
                errors=["Cancelled during collection."],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 5. Simulate malformed output
        if self.simulate_malformed or "malformed" in target.lower():
            # Return an observation with invalid/unparseable values
            return OSINTAdapterResult(
                adapter_name=self.adapter_name,
                adapter_version=self.adapter_version,
                success=True,
                observations=[
                    OSINTRawObservation(
                        target="http://user:pass@invalid target with spaces.com:999999/path",
                        target_type=AssetType.URL,
                        data={"malformed": True},
                    )
                ],
                execution_time_seconds=time.monotonic() - start_time,
            )

        # 6. Generate synthetic deterministic observations
        now = datetime.now(UTC)
        observations: list[OSINTRawObservation] = []

        clean_target = target.strip().lower().rstrip(".")

        # Observation 1: Target host DNS resolution records
        dns_data = {
            "query_target": clean_target,
            "records": {
                "A": ["192.168.1.10"],
                "CNAME": [f"alias.{clean_target}"],
                "TXT": ["v=spf1 -all"],
                "MX": [f"mail.{clean_target}"],
            },
            "authoritative": True,
        }
        observations.append(
            OSINTRawObservation(
                target=clean_target,
                target_type=TargetType.DOMAIN,
                confidence=1.0,
                data=dns_data,
                raw_payload=json.dumps(dns_data, sort_keys=True).encode("utf-8"),
                sanitized_excerpt=f"Resolved DNS records for {clean_target}: 192.168.1.10",
                relationships={"resolves_to_ip": ["192.168.1.10"]},
                metadata={"dns_server": "synthetic_mock_dns"},
                collected_at=now,
            )
        )

        # Observation 2: Discovered IP address
        observations.append(
            OSINTRawObservation(
                target="192.168.1.10",
                target_type=TargetType.IP_ADDRESS,
                confidence=1.0,
                data={"ip": "192.168.1.10", "reverse_dns": clean_target},
                sanitized_excerpt=f"Associated IP 192.168.1.10 resolving to {clean_target}",
                relationships={"resolves_from_domain": [clean_target]},
                collected_at=now,
            )
        )

        # Observation 3: In-scope or expected subdomain
        subdomain_in_scope = f"api.{clean_target}"
        observations.append(
            OSINTRawObservation(
                target=subdomain_in_scope,
                target_type=TargetType.DOMAIN,
                confidence=0.95,
                data={"subdomain": subdomain_in_scope, "source": "ct_logs"},
                sanitized_excerpt=f"Discovered subdomain {subdomain_in_scope} from CT logs",
                relationships={"subdomain_of": [clean_target]},
                collected_at=now,
            )
        )

        # Observation 4: Out-of-scope candidate (to test candidate scope separation)
        out_of_scope_candidate = "external-unauthorized.test"
        observations.append(
            OSINTRawObservation(
                target=out_of_scope_candidate,
                target_type=TargetType.DOMAIN,
                confidence=0.8,
                data={"subdomain": out_of_scope_candidate, "source": "passive_cname"},
                sanitized_excerpt=f"Observed reference to {out_of_scope_candidate}",
                relationships={"referenced_by": [clean_target]},
                collected_at=now,
            )
        )

        # Observation 5: Web application service
        web_app_url = f"http://{clean_target}:8080/health"
        observations.append(
            OSINTRawObservation(
                target=web_app_url,
                target_type=AssetType.URL,
                confidence=0.9,
                data={"url": web_app_url, "status": 200, "server": "mock_nginx/1.24"},
                sanitized_excerpt=f"Discovered HTTP service on {clean_target}:8080/health",
                relationships={"hosted_on": [clean_target]},
                collected_at=now,
            )
        )

        elapsed = time.monotonic() - start_time
        return OSINTAdapterResult(
            adapter_name=self.adapter_name,
            adapter_version=self.adapter_version,
            success=True,
            observations=observations,
            errors=[],
            execution_time_seconds=elapsed,
        )
