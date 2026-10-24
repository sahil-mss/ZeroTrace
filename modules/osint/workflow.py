import logging
from typing import Any

from backend.policy.scope_validator import ScopeValidator
from backend.storage.database import DatabaseManager
from backend.storage.evidence_store import EvidenceStore
from modules.osint.crtsh_adapter import CertTransparencyAdapter
from modules.osint.dns_adapter import DnsLookupAdapter
from modules.osint.http_adapter import HttpFingerprintAdapter
from modules.osint.normalizer import AssetNormalizer
from schemas.enums import AssetType, ScopeStatus
from schemas.models import Assessment, Job

logger = logging.getLogger("aegispt.osint.workflow")


class OsintWorkflow:
    """
    Coordinates passive intelligence collection across DNS, CT logs, and HTTP fingerprinting.
    Feeds normalized assets and cryptographic evidence into the central store.
    """

    def __init__(self, db: DatabaseManager, evidence_store: EvidenceStore):
        self.db = db
        self.evidence_store = evidence_store
        self.normalizer = AssetNormalizer(db)
        self.dns_adapter = DnsLookupAdapter(evidence_store)
        self.crtsh_adapter = CertTransparencyAdapter(evidence_store)
        self.http_adapter = HttpFingerprintAdapter(evidence_store)

    async def handle_dns_job(self, job: Job, assessment: Assessment) -> dict[str, Any]:
        """Runs DNS resolution for target and correlates IP/CNAME assets."""
        res = self.dns_adapter.query(assessment.assessment_id, job.target_input)
        evidence = res["evidence"]
        self.db.save_evidence(evidence)

        # Create or update domain asset
        domain_asset, _ = self.normalizer.normalize_and_store_asset(
            assessment_id=assessment.assessment_id,
            raw_value=job.target_input,
            asset_type=AssetType.DOMAIN,
            source_evidence_id=evidence.evidence_id,
            scope_policy=assessment.scope,
            confidence=1.0,
        )

        # Correlate resolved IPs & CNAMEs
        created_assets = self.normalizer.correlate_dns_records(
            assessment_id=assessment.assessment_id,
            domain_asset=domain_asset,
            dns_records=res["records"],
            evidence_id=evidence.evidence_id,
            scope_policy=assessment.scope,
        )

        return {
            "records": res["records"],
            "evidence_id": evidence.evidence_id,
            "associated_assets_count": len(created_assets),
        }

    async def handle_crtsh_job(self, job: Job, assessment: Assessment) -> dict[str, Any]:
        """Discovers subdomains from Certificate Transparency logs and validates scope."""
        res = await self.crtsh_adapter.query(assessment.assessment_id, job.target_input)
        evidence = res["evidence"]
        self.db.save_evidence(evidence)

        subdomains = res.get("subdomains", [])
        in_scope_count = 0
        out_of_scope_count = 0

        for sub in subdomains:
            # Enforce scope check on each discovered subdomain!
            in_scope, reason, status = ScopeValidator.is_in_scope(sub, assessment.scope)
            asset, is_new = self.normalizer.normalize_and_store_asset(
                assessment_id=assessment.assessment_id,
                raw_value=sub,
                asset_type=AssetType.SUBDOMAIN,
                source_evidence_id=evidence.evidence_id,
                scope_policy=assessment.scope,
                confidence=0.95,
                relationships={"subdomain_of": [job.target_input]},
            )
            if status == ScopeStatus.IN_SCOPE:
                in_scope_count += 1
            else:
                out_of_scope_count += 1

        return {
            "total_discovered": len(subdomains),
            "in_scope_count": in_scope_count,
            "out_of_scope_count": out_of_scope_count,
            "evidence_id": evidence.evidence_id,
        }

    async def handle_http_fingerprint_job(self, job: Job, assessment: Assessment) -> dict[str, Any]:
        """Probes HTTP endpoint, extracts headers, banners, and security attributes."""
        res = await self.http_adapter.probe(assessment.assessment_id, job.target_input)
        evidence = res["evidence"]
        self.db.save_evidence(evidence)

        # Update or store web application asset
        app_asset, _ = self.normalizer.normalize_and_store_asset(
            assessment_id=assessment.assessment_id,
            raw_value=job.target_input,
            asset_type=AssetType.WEB_APPLICATION,
            source_evidence_id=evidence.evidence_id,
            scope_policy=assessment.scope,
            confidence=1.0,
            metadata={
                "server_banner": res.get("server"),
                "x_powered_by": res.get("x_powered_by"),
                "status_code": res.get("status_code"),
                "missing_security_headers": res.get("missing_security_headers", []),
            },
        )

        return {
            "url": res.get("url"),
            "status_code": res.get("status_code"),
            "server": res.get("server"),
            "missing_security_headers": res.get("missing_security_headers", []),
            "evidence_id": evidence.evidence_id,
        }

    async def handle_full_passive_recon(self, job: Job, assessment: Assessment) -> dict[str, Any]:
        """Coordinates comprehensive passive intelligence collection for target."""
        dns_res = await self.handle_dns_job(job, assessment)
        crtsh_res = await self.handle_crtsh_job(job, assessment)
        http_res = await self.handle_http_fingerprint_job(job, assessment)

        return {
            "dns": dns_res,
            "cert_transparency": crtsh_res,
            "http_fingerprint": http_res,
        }
