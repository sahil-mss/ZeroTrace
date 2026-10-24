"""
Asset Service for ZeroTrace / AegisPT.

Manages asset normalization, deterministic scope classification, deduplication within
assessment boundaries, evidence linking, and graph relationship correlation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from aegis_common.enums import AssetType, ScopeStatus
from aegis_common.models import Asset
from aegis_common.utils import utc_now
from backend.app.db.models import EvidenceModel
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.repositories.asset_repo import AssetRepository
from backend.app.services.normalization import infer_and_normalize_asset_target
from backend.app.services.scope_validator import ScopeValidator


@dataclass
class AssetObservation:
    """Structured observation of an asset candidate from a tool or OSINT source."""

    assessment_id: str
    raw_value: str
    asset_type: AssetType | None = None
    source_evidence_id: str | None = None
    confidence: float = 1.0
    is_inferred: bool = False
    relationships: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime | None = None


class AssetService:
    """
    Asset Service managing normalization, scope enforcement, and deduplication
    across assessment boundaries.
    """

    def __init__(self, session: Session):
        self.session = session
        self.asset_repo = AssetRepository(session)
        self.assessment_repo = AssessmentRepository(session)

    def register_asset(self, observation: AssetObservation) -> tuple[Asset, bool]:
        """
        Normalizes target value, evaluates scope against the assessment, enforces
        immutability of OUT_OF_SCOPE status, links evidence, and deduplicates.

        Returns: (Asset, is_new: bool)
        """
        # 1. Validate Assessment Exists
        assessment_domain = self.assessment_repo.get(observation.assessment_id)
        if not assessment_domain:
            raise ValueError(
                f"Cannot register asset: Assessment '{observation.assessment_id}' does not exist."
            )

        # 2. Normalize Target and Determine AssetType
        normalized_value, resolved_type = infer_and_normalize_asset_target(
            raw_target=observation.raw_value,
            explicit_type=observation.asset_type,
        )

        # 3. Apply Scope Validation Before Marking IN_SCOPE
        # An asset discovered through OSINT or scanning must never automatically inherit scope
        validation_result = ScopeValidator.validate_target(
            target=normalized_value,
            assessment_scope=assessment_domain,
        )
        calculated_scope_status = (
            ScopeStatus.IN_SCOPE if validation_result.allowed else ScopeStatus.OUT_OF_SCOPE
        )

        # 4. Validate Source Evidence Reference if Provided
        if observation.source_evidence_id:
            evidence_model = self.session.get(EvidenceModel, observation.source_evidence_id)
            if not evidence_model:
                raise ValueError(
                    f"Cannot link evidence: Evidence '{observation.source_evidence_id}' does not exist."
                )
            if evidence_model.assessment_id != observation.assessment_id:
                raise ValueError(
                    f"Cross-assessment boundary violation: Evidence '{observation.source_evidence_id}' "
                    f"belongs to assessment '{evidence_model.assessment_id}', but asset was registered "
                    f"for assessment '{observation.assessment_id}'."
                )

        now = observation.observed_at or utc_now()

        # 5. Check for Existing Asset (Deduplication within Assessment Boundary)
        existing_asset = self.asset_repo.get_by_value(observation.assessment_id, normalized_value)

        if existing_asset:
            # Rule: Never change an out-of-scope asset into an approved one simply because another source reports it
            final_scope_status = existing_asset.scope_classification
            if existing_asset.scope_classification == ScopeStatus.OUT_OF_SCOPE:
                final_scope_status = ScopeStatus.OUT_OF_SCOPE
            elif calculated_scope_status == ScopeStatus.IN_SCOPE:
                final_scope_status = ScopeStatus.IN_SCOPE

            # Update timestamps, confidence, metadata, relationships
            updated_confidence = max(existing_asset.confidence, observation.confidence)

            # Merge evidence IDs
            merged_evidence = list(existing_asset.source_evidence_ids)
            if (
                observation.source_evidence_id
                and observation.source_evidence_id not in merged_evidence
            ):
                merged_evidence.append(observation.source_evidence_id)

            # Merge relationships
            merged_rels = dict(existing_asset.relationships)
            for rel_k, rel_v in observation.relationships.items():
                merged_rels.setdefault(rel_k, [])
                for item in rel_v:
                    if item not in merged_rels[rel_k]:
                        merged_rels[rel_k].append(item)

            # Merge metadata
            merged_metadata = dict(existing_asset.metadata)
            if observation.metadata:
                merged_metadata.update(observation.metadata)

            updated_asset = Asset(
                asset_id=existing_asset.asset_id,
                assessment_id=existing_asset.assessment_id,
                asset_type=resolved_type,
                normalized_value=normalized_value,
                scope_classification=final_scope_status,
                confidence=updated_confidence,
                source_evidence_ids=merged_evidence,
                is_inferred=existing_asset.is_inferred and observation.is_inferred,
                directly_observed=existing_asset.directly_observed or not observation.is_inferred,
                relationships=merged_rels,
                metadata=merged_metadata,
                first_seen=existing_asset.first_seen,
                last_seen=now,
            )
            saved = self.asset_repo.update(updated_asset)

            # If evidence needs back-reference to asset
            if observation.source_evidence_id:
                evidence_model = self.session.get(EvidenceModel, observation.source_evidence_id)
                if evidence_model and not evidence_model.asset_id:
                    evidence_model.asset_id = saved.asset_id

            self.session.flush()
            return saved, False

        # 6. Create New Asset
        new_asset = Asset(
            assessment_id=observation.assessment_id,
            asset_type=resolved_type,
            normalized_value=normalized_value,
            scope_classification=calculated_scope_status,
            confidence=observation.confidence,
            source_evidence_ids=[observation.source_evidence_id]
            if observation.source_evidence_id
            else [],
            is_inferred=observation.is_inferred,
            directly_observed=not observation.is_inferred,
            relationships=observation.relationships,
            metadata=observation.metadata,
            first_seen=now,
            last_seen=now,
        )
        saved = self.asset_repo.create(new_asset)

        # Back-link evidence to the newly created asset
        if observation.source_evidence_id:
            evidence_model = self.session.get(EvidenceModel, observation.source_evidence_id)
            if evidence_model and not evidence_model.asset_id:
                evidence_model.asset_id = saved.asset_id

        self.session.flush()
        return saved, True

    def link_evidence(self, assessment_id: str, asset_id: str, evidence_id: str) -> Asset:
        """
        Explicitly associates an evidence record with a target asset.
        Rejects cross-assessment links.
        """
        asset = self.asset_repo.get(asset_id)
        if not asset:
            raise ValueError(f"Cannot link evidence: Asset '{asset_id}' does not exist.")
        if asset.assessment_id != assessment_id:
            raise ValueError(
                f"Cross-assessment violation: Asset '{asset_id}' belongs to assessment '{asset.assessment_id}', not '{assessment_id}'."
            )

        evidence_model = self.session.get(EvidenceModel, evidence_id)
        if not evidence_model:
            raise ValueError(f"Cannot link evidence: Evidence '{evidence_id}' does not exist.")
        if evidence_model.assessment_id != assessment_id:
            raise ValueError(
                f"Cross-assessment violation: Evidence '{evidence_id}' belongs to assessment '{evidence_model.assessment_id}', not '{assessment_id}'."
            )

        if evidence_id not in asset.source_evidence_ids:
            asset.source_evidence_ids.append(evidence_id)
            asset = self.asset_repo.update(asset)

        if evidence_model.asset_id != asset_id:
            evidence_model.asset_id = asset_id

        self.session.flush()
        return asset

    def get_asset(self, asset_id: str) -> Asset | None:
        """Retrieves asset by unique ID."""
        return self.asset_repo.get(asset_id)

    def get_asset_by_value(self, assessment_id: str, normalized_value: str) -> Asset | None:
        """Retrieves asset by assessment ID and normalized target value."""
        return self.asset_repo.get_by_value(assessment_id, normalized_value)

    def list_assets(
        self, assessment_id: str, scope_filter: ScopeStatus | None = None
    ) -> list[Asset]:
        """Lists assets for an assessment, with optional scope classification filtering."""
        all_assets = self.asset_repo.list_by_assessment(assessment_id)
        if scope_filter is not None:
            return [a for a in all_assets if a.scope_classification == scope_filter]
        return all_assets

    def correlate_dns_records(
        self,
        assessment_id: str,
        domain_asset: Asset,
        dns_records: dict[str, list[str]],
        evidence_id: str,
    ) -> list[Asset]:
        """
        Extracts A/AAAA IPs and CNAMEs from DNS evidence, registers linked Asset records,
        and establishes bidirectional graph relationships.
        """
        created_assets: list[Asset] = []

        # 1. Correlate IP addresses (A / AAAA)
        ip_list = dns_records.get("A", []) + dns_records.get("AAAA", [])
        for ip in ip_list:
            ip_obs = AssetObservation(
                assessment_id=assessment_id,
                raw_value=ip,
                asset_type=AssetType.IP_ADDRESS,
                source_evidence_id=evidence_id,
                confidence=1.0,
                relationships={"resolves_from_domain": [domain_asset.normalized_value]},
                metadata={"dns_resolved": True},
            )
            ip_asset, _ = self.register_asset(ip_obs)
            created_assets.append(ip_asset)

            # Add reverse relationship to domain asset
            domain_asset.relationships.setdefault("resolves_to_ip", [])
            if ip_asset.normalized_value not in domain_asset.relationships["resolves_to_ip"]:
                domain_asset.relationships["resolves_to_ip"].append(ip_asset.normalized_value)

        # 2. Correlate CNAMEs
        for cname in dns_records.get("CNAME", []):
            cname_obs = AssetObservation(
                assessment_id=assessment_id,
                raw_value=cname,
                asset_type=AssetType.DOMAIN,
                source_evidence_id=evidence_id,
                confidence=0.9,
                relationships={"cname_for": [domain_asset.normalized_value]},
            )
            cname_asset, _ = self.register_asset(cname_obs)
            created_assets.append(cname_asset)

        self.asset_repo.update(domain_asset)
        self.session.flush()
        return created_assets
