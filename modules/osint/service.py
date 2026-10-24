"""
OSINT Collection Service for ZeroTrace / AegisPT.

Orchestrates pluggable, passive OSINT source adapters with strict assessment lifecycle
validation, pre-execution scope checks, resource budgets, cooperative cancellation,
normalization, evidence recording, and asset registry integration.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    AuditOutcome,
    ScopeStatus,
)
from aegis_common.models import AuditEvent
from aegis_common.utils import utc_now
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.repositories.audit_repo import AuditRepository
from backend.app.services.asset_service import AssetObservation, AssetService
from backend.app.services.evidence_service import EvidenceObservation, EvidenceService
from backend.app.services.scope_validator import ScopeValidator
from modules.osint.contracts import (
    BaseOSINTAdapter,
    CancellationToken,
    OSINTCollectionContext,
)
from modules.osint.crtsh_adapter import CertificateTransparencyAdapter
from modules.osint.dns_adapter import DNSMetadataAdapter
from modules.osint.mock_adapter import MockOSINTAdapter

logger = logging.getLogger("zerotrace.osint.service")


@dataclass
class OSINTCollectionSummary:
    """Structured result returned by the OSINT collection framework."""

    assessment_id: str
    status: str  # "COMPLETED", "PARTIAL_FAILURE", "FAILED", "CANCELLED"
    total_targets_queried: int
    adapters_executed: list[str] = field(default_factory=list)
    new_assets_created: int = 0
    duplicate_assets_updated: int = 0
    evidence_records_created: int = 0
    evidence_records_deduplicated: int = 0
    candidate_assets_out_of_scope: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class OSINTCollectionService:
    """
    Modular OSINT Collection Service coordinating passive intelligence collection.
    Integrates with deterministic ScopeValidator, EvidenceService, and AssetService.
    """

    def __init__(
        self,
        session: Session,
        adapters: list[BaseOSINTAdapter] | None = None,
    ):
        self.session = session
        self.assessment_repo = AssessmentRepository(session)
        self.audit_repo = AuditRepository(session)
        self.evidence_service = EvidenceService(session)
        self.asset_service = AssetService(session)

        # Register default adapters if none provided
        if adapters is not None:
            self._adapters: dict[str, BaseOSINTAdapter] = {a.adapter_name: a for a in adapters}
        else:
            mock = MockOSINTAdapter()
            dns_adapter = DNSMetadataAdapter()
            ct_adapter = CertificateTransparencyAdapter()
            self._adapters = {
                mock.adapter_name: mock,
                dns_adapter.adapter_name: dns_adapter,
                ct_adapter.adapter_name: ct_adapter,
            }

    def register_adapter(self, adapter: BaseOSINTAdapter) -> None:
        """Dynamically registers or updates an OSINT source adapter."""
        self._adapters[adapter.adapter_name] = adapter

    def get_adapter(self, adapter_name: str) -> BaseOSINTAdapter | None:
        """Retrieves a registered adapter by name."""
        return self._adapters.get(adapter_name)

    def list_adapters(self) -> list[BaseOSINTAdapter]:
        """Lists all registered adapters."""
        return list(self._adapters.values())

    async def run_collection(
        self,
        assessment_id: str,
        target: str | None = None,
        adapter_names: list[str] | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> OSINTCollectionSummary:
        """
        Executes bounded, deterministic OSINT collection across authorized targets.
        """
        start_time = time.monotonic()
        token = cancellation_token or CancellationToken()

        # 1. Confirm Assessment is Approved and Not Expired (Fail Closed)
        assessment = self.assessment_repo.get(assessment_id)
        if not assessment:
            raise ValueError(f"Cannot run OSINT: Assessment '{assessment_id}' does not exist.")

        if assessment.lifecycle_status not in (AssessmentStatus.APPROVED, AssessmentStatus.ACTIVE):
            self._log_audit(
                assessment_id=assessment_id,
                event_type="OSINT_COLLECTION_DENIED",
                outcome=AuditOutcome.DENIED,
                metadata={
                    "reason": f"Assessment lifecycle status is {assessment.lifecycle_status.value}"
                },
            )
            raise ValueError(
                f"Assessment '{assessment_id}' is not approved (status: {assessment.lifecycle_status.value})."
            )

        now = utc_now()
        if assessment.expires_at and now > assessment.expires_at:
            self._log_audit(
                assessment_id=assessment_id,
                event_type="OSINT_COLLECTION_DENIED",
                outcome=AuditOutcome.DENIED,
                metadata={"reason": f"Assessment expired on {assessment.expires_at.isoformat()}"},
            )
            raise ValueError(f"Assessment '{assessment_id}' has expired (fail closed).")

        # 2. Determine Permitted Targets
        if target:
            # Check scope for explicitly requested target
            res = ScopeValidator.validate_target(target, assessment)
            if not res.allowed:
                self._log_audit(
                    assessment_id=assessment_id,
                    event_type="OSINT_TARGET_SCOPE_DENIED",
                    outcome=AuditOutcome.DENIED,
                    metadata={"target": target, "reason": res.explanation},
                )
                raise ValueError(f"Target '{target}' is not in approved scope: {res.explanation}")
            targets_to_query = [target]
        else:
            # Derive approved targets from assessment scope rules or policy
            targets_to_query = []
            for rule in assessment.scope_rules:
                if not rule.exclude:
                    clean = rule.target_value.strip().lower().lstrip("*.")
                    if clean and clean not in targets_to_query:
                        targets_to_query.append(clean)

            if not targets_to_query and assessment.scope:
                for domain in assessment.scope.target_domains:
                    clean = domain.strip().lower()
                    if clean and clean not in targets_to_query:
                        targets_to_query.append(clean)

        if not targets_to_query:
            raise ValueError(
                f"Assessment '{assessment_id}' has no approved targets configured in scope."
            )

        # 3. Select Enabled Adapters with Approved Permission Levels
        selected_adapters: list[BaseOSINTAdapter] = []
        for name, adapter in self._adapters.items():
            if not adapter.enabled:
                continue
            if adapter_names and name not in adapter_names:
                continue
            # Validate permissions
            if adapter.required_permission not in assessment.permitted_profiles:
                logger.warning(
                    f"Skipping adapter '{name}': required profile {adapter.required_permission.value} "
                    f"not in permitted assessment profiles."
                )
                continue
            selected_adapters.append(adapter)

        if not selected_adapters:
            raise ValueError(
                f"No enabled, authorized OSINT adapters found for assessment '{assessment_id}'."
            )

        # Record start audit event
        self._log_audit(
            assessment_id=assessment_id,
            event_type="OSINT_COLLECTION_STARTED",
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "targets_count": len(targets_to_query),
                "adapters": [a.adapter_name for a in selected_adapters],
            },
        )

        summary = OSINTCollectionSummary(
            assessment_id=assessment_id,
            status="COMPLETED",
            total_targets_queried=len(targets_to_query),
            adapters_executed=[a.adapter_name for a in selected_adapters],
        )

        context = OSINTCollectionContext(
            assessment_id=assessment_id,
            approved_targets=targets_to_query,
            scope_validator=ScopeValidator(),
            cancellation_token=token,
            session=self.session,
        )

        # 4. Execute Collection per Target and Adapter
        for current_target in targets_to_query:
            if token.is_cancelled:
                summary.status = "CANCELLED"
                summary.errors.append(f"Collection cancelled: {token.reason}")
                break

            # Pre-execution Scope Revalidation
            scope_check = ScopeValidator.validate_target(current_target, assessment)
            if not scope_check.allowed:
                summary.errors.append(
                    f"Target '{current_target}' failed pre-execution scope check: {scope_check.explanation}"
                )
                continue

            for adapter in selected_adapters:
                if token.is_cancelled:
                    summary.status = "CANCELLED"
                    break

                try:
                    # Apply resource timeout budget
                    timeout = adapter.resource_budget.timeout_seconds
                    adapter_result = await asyncio.wait_for(
                        adapter.collect(current_target, context),
                        timeout=timeout,
                    )

                    if not adapter_result.success:
                        err_msg = (
                            f"Adapter '{adapter.adapter_name}' reported failure for '{current_target}': "
                            + "; ".join(adapter_result.errors)
                        )
                        summary.errors.append(err_msg)
                        self._log_audit(
                            assessment_id=assessment_id,
                            event_type="OSINT_ADAPTER_ERROR",
                            outcome=AuditOutcome.FAILURE,
                            metadata={
                                "adapter": adapter.adapter_name,
                                "target": current_target,
                                "error": err_msg,
                            },
                        )
                        continue

                    # Process structured observations through EvidenceService and AssetService
                    for obs in adapter_result.observations:
                        try:
                            # 6a. Record verifiable Evidence record
                            evi_obs = EvidenceObservation(
                                assessment_id=assessment_id,
                                source_name=adapter.adapter_name,
                                source_type=adapter.source_type,
                                collection_method="OSINT_PASSIVE",
                                data=obs.data,
                                raw_payload=obs.raw_payload,
                                sanitized_excerpt=obs.sanitized_excerpt,
                                metadata=obs.metadata,
                                tool_version=adapter.adapter_version,
                                collected_at=obs.collected_at,
                            )
                            saved_evidence, evi_is_new = self.evidence_service.ingest_observation(
                                evi_obs
                            )
                            if evi_is_new:
                                summary.evidence_records_created += 1
                            else:
                                summary.evidence_records_deduplicated += 1

                            # 6b. Register and classify Asset
                            asset_obs = AssetObservation(
                                assessment_id=assessment_id,
                                raw_value=obs.target,
                                asset_type=obs.target_type,
                                source_evidence_id=saved_evidence.evidence_id,
                                confidence=obs.confidence,
                                relationships=obs.relationships,
                                metadata=obs.metadata,
                                observed_at=obs.collected_at,
                            )
                            saved_asset, asset_is_new = self.asset_service.register_asset(asset_obs)
                            if asset_is_new:
                                summary.new_assets_created += 1
                            else:
                                summary.duplicate_assets_updated += 1

                            # Check if candidate is out-of-scope
                            if saved_asset.scope_classification != ScopeStatus.IN_SCOPE:
                                summary.candidate_assets_out_of_scope += 1

                        except Exception as obs_err:
                            summary.errors.append(f"Observation processing error: {obs_err}")

                except TimeoutError:
                    timeout_msg = (
                        f"Adapter '{adapter.adapter_name}' timed out after {adapter.resource_budget.timeout_seconds}s "
                        f"on target '{current_target}'."
                    )
                    summary.errors.append(timeout_msg)
                    self._log_audit(
                        assessment_id=assessment_id,
                        event_type="OSINT_ADAPTER_TIMEOUT",
                        outcome=AuditOutcome.FAILURE,
                        metadata={"adapter": adapter.adapter_name, "target": current_target},
                    )

                except Exception as exc:
                    exc_msg = f"Adapter '{adapter.adapter_name}' raised unexpected exception: {exc}"
                    summary.errors.append(exc_msg)
                    self._log_audit(
                        assessment_id=assessment_id,
                        event_type="OSINT_ADAPTER_FAILED",
                        outcome=AuditOutcome.FAILURE,
                        metadata={"adapter": adapter.adapter_name, "error": str(exc)},
                    )

        # Final Status Calculation
        if summary.status != "CANCELLED":
            if summary.errors and (
                summary.new_assets_created > 0 or summary.evidence_records_created > 0
            ):
                summary.status = "PARTIAL_FAILURE"
            elif (
                summary.errors
                and summary.new_assets_created == 0
                and summary.evidence_records_created == 0
            ):
                summary.status = "FAILED"
            else:
                summary.status = "COMPLETED"

        summary.duration_seconds = time.monotonic() - start_time

        # Record completion audit event
        self._log_audit(
            assessment_id=assessment_id,
            event_type="OSINT_COLLECTION_COMPLETED",
            outcome=AuditOutcome.SUCCESS if summary.status == "COMPLETED" else AuditOutcome.FAILURE,
            metadata={
                "status": summary.status,
                "new_assets": summary.new_assets_created,
                "evidence_records": summary.evidence_records_created,
                "errors_count": len(summary.errors),
                "duration_seconds": summary.duration_seconds,
            },
        )
        self.session.commit()
        return summary

    def _log_audit(
        self,
        assessment_id: str,
        event_type: str,
        outcome: AuditOutcome,
        metadata: dict[str, Any],
    ) -> None:
        """Helper to append an immutable audit record."""
        try:
            event = AuditEvent(
                assessment_id=assessment_id,
                event_type=event_type,
                actor="osint_service",
                outcome=outcome,
                sanitized_metadata=metadata,
                timestamp=datetime.now(UTC),
            )
            self.audit_repo.record(event)
            self.session.flush()
        except Exception as e:
            logger.error(f"Failed to record audit event {event_type}: {e}")
