import ipaddress
from typing import Any

from backend.policy.scope_validator import ScopeValidator
from backend.storage.database import DatabaseManager
from schemas.enums import AssetType, ScopeStatus
from schemas.models import Asset, ScopePolicy, utc_now


class AssetNormalizer:
    """
    Asset Normalization, Correlation, and Deduplication Engine.
    Converts raw OSINT and scanner observations into canonical Asset records,
    correlates relationships, and enforces scope boundaries.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    def normalize_and_store_asset(
        self,
        assessment_id: str,
        raw_value: str,
        asset_type: AssetType | None = None,
        source_evidence_id: str | None = None,
        scope_policy: ScopePolicy | None = None,
        confidence: float = 1.0,
        relationships: dict[str, list[str]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Asset, bool]:
        """
        Normalizes a target value, checks/updates database, and correlates relationships.
        Returns: (asset: Asset, is_new: bool)
        """
        canon = ScopeValidator.canonicalize(raw_value)
        hostname = canon["hostname"]

        # Infer asset type if not provided
        if asset_type is None:
            try:
                ipaddress.ip_address(hostname)
                asset_type = AssetType.IP_ADDRESS
            except ValueError:
                if canon["scheme"] or canon["port"]:
                    asset_type = AssetType.WEB_APPLICATION
                elif "." in hostname and hostname.count(".") > 1:
                    asset_type = AssetType.SUBDOMAIN
                else:
                    asset_type = AssetType.DOMAIN

        # Canonical value format
        if canon["port"]:
            canonical_value = f"{hostname}:{canon['port']}"
        else:
            canonical_value = hostname

        # Evaluate scope status
        scope_status = ScopeStatus.PENDING_REVIEW
        if scope_policy:
            in_scope, reason, status = ScopeValidator.is_in_scope(canonical_value, scope_policy)
            scope_status = status

        # Check existing asset in database
        existing_asset = self.db.get_asset_by_value(assessment_id, canonical_value)

        if existing_asset:
            # Update existing asset
            if source_evidence_id and source_evidence_id not in existing_asset.source_evidence_ids:
                existing_asset.source_evidence_ids.append(source_evidence_id)

            if relationships:
                for rel_key, rel_list in relationships.items():
                    existing_list = existing_asset.relationships.setdefault(rel_key, [])
                    for item in rel_list:
                        if item not in existing_list:
                            existing_list.append(item)

            if metadata:
                existing_asset.metadata.update(metadata)

            existing_asset.last_observed = utc_now()
            # If previously pending and now verified in scope, update
            if scope_policy and existing_asset.scope_status != scope_status:
                existing_asset.scope_status = scope_status

            saved = self.db.save_asset(existing_asset)
            return saved, False
        else:
            # Create new Asset
            new_asset = Asset(
                assessment_id=assessment_id,
                asset_type=asset_type,
                value=canonical_value,
                scope_status=scope_status,
                confidence=confidence,
                source_evidence_ids=[source_evidence_id] if source_evidence_id else [],
                relationships=relationships or {},
                metadata=metadata or {},
                first_observed=utc_now(),
                last_observed=utc_now(),
            )
            saved = self.db.save_asset(new_asset)
            return saved, True

    def correlate_dns_records(
        self,
        assessment_id: str,
        domain_asset: Asset,
        dns_records: dict[str, list[str]],
        evidence_id: str,
        scope_policy: ScopePolicy | None = None,
    ) -> list[Asset]:
        """
        Extracts IPs (A/AAAA) and CNAMEs from DNS evidence, creates linked Asset records,
        and builds graph relationships (domain -> resolved_ip, domain -> cname).
        """
        created_assets: list[Asset] = []

        # Correlate A and AAAA IPs
        ip_list = dns_records.get("A", []) + dns_records.get("AAAA", [])
        for ip in ip_list:
            ip_asset, is_new = self.normalize_and_store_asset(
                assessment_id=assessment_id,
                raw_value=ip,
                asset_type=AssetType.IP_ADDRESS,
                source_evidence_id=evidence_id,
                scope_policy=scope_policy,
                confidence=1.0,
                relationships={"resolves_from_domain": [domain_asset.value]},
                metadata={"dns_resolved": True},
            )
            created_assets.append(ip_asset)

            # Update reverse link on domain asset
            domain_asset.relationships.setdefault("resolves_to_ip", [])
            if ip_asset.value not in domain_asset.relationships["resolves_to_ip"]:
                domain_asset.relationships["resolves_to_ip"].append(ip_asset.value)

        # Correlate CNAMEs
        for cname in dns_records.get("CNAME", []):
            cname_asset, is_new = self.normalize_and_store_asset(
                assessment_id=assessment_id,
                raw_value=cname,
                asset_type=AssetType.DOMAIN,
                source_evidence_id=evidence_id,
                scope_policy=scope_policy,
                confidence=0.9,
                relationships={"cname_for": [domain_asset.value]},
            )
            created_assets.append(cname_asset)

        self.db.save_asset(domain_asset)
        return created_assets
