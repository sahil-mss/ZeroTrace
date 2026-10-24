import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from schemas.contracts import (
    Assessment,
    Asset,
    DiscoveredService,
    Evidence,
    Finding,
    get_utc_now,
)
from schemas.enums import (
    AssessmentStatus,
    AssetType,
    ConfidenceLevel,
    FindingSeverity,
    VerificationStatus,
)

logger = logging.getLogger("aegispt.adapter.integration")


class UpstreamNormalizer:
    """
    Lightweight, resilient adapter layer normalizing raw upstream OSINT,
    scanner, and database records into shared ZeroTrace/AegisPT contracts.
    """

    @staticmethod
    def parse_datetime(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str) and val.strip():
            try:
                # Handle ISO strings
                clean = val.replace("Z", "+00:00")
                return datetime.fromisoformat(clean)
            except Exception:
                pass
        return get_utc_now()

    @classmethod
    def normalize_assessment(cls, raw: Dict[str, Any]) -> Assessment:
        """
        Normalizes upstream assessment representation.
        Handles both Person 1 schema ('assessment_id', 'title', 'scope.target_urls')
        and Person 3 schema ('id', 'name', 'target').
        """
        aid = raw.get("assessment_id") or raw.get("id") or "assess_unknown"
        name = raw.get("title") or raw.get("name") or "Security Assessment"

        # Resolve primary target from scope if available
        target = raw.get("target") or ""
        if not target and isinstance(raw.get("scope"), dict):
            scope_dict = raw["scope"]
            urls = scope_dict.get("target_urls") or []
            domains = scope_dict.get("target_domains") or []
            ips = scope_dict.get("target_ips") or []
            if urls:
                target = urls[0]
            elif domains:
                target = domains[0]
            elif ips:
                target = ips[0]

        if not target:
            target = "127.0.0.1"

        # Normalize status
        raw_status = str(raw.get("status", "")).upper()
        status_map = {
            "DRAFT": AssessmentStatus.PENDING,
            "APPROVED": AssessmentStatus.PENDING,
            "PENDING": AssessmentStatus.PENDING,
            "ACTIVE": AssessmentStatus.IN_PROGRESS,
            "IN_PROGRESS": AssessmentStatus.IN_PROGRESS,
            "PAUSED": AssessmentStatus.IN_PROGRESS,
            "COMPLETED": AssessmentStatus.COMPLETED,
            "FAILED": AssessmentStatus.FAILED,
            "CANCELLED": AssessmentStatus.CANCELLED,
        }
        status = status_map.get(raw_status, AssessmentStatus.PENDING)

        created_at = cls.parse_datetime(raw.get("created_at"))
        completed_at = cls.parse_datetime(raw.get("completed_at")) if raw.get("completed_at") else None

        return Assessment(
            id=aid,
            name=name,
            target=target,
            status=status,
            created_at=created_at,
            completed_at=completed_at,
        )

    @classmethod
    def normalize_asset(cls, raw: Dict[str, Any], fallback_assessment_id: str = "assess_unknown") -> Asset:
        """
        Normalizes upstream OSINT or port scan asset records.
        Maps Person 1 'value'/'asset_id' or scanner output into shared Asset.
        """
        asset_id = raw.get("asset_id") or raw.get("id") or f"asset_{hash(str(raw)) % 1000000}"
        assessment_id = raw.get("assessment_id") or fallback_assessment_id

        # Target hostname or address
        host_val = raw.get("hostname_or_address") or raw.get("value") or raw.get("target") or "unknown_host"

        # Classify asset type
        raw_type = str(raw.get("asset_type", "")).upper()
        type_map = {
            "DOMAIN": AssetType.DOMAIN,
            "SUBDOMAIN": AssetType.DOMAIN,
            "IP_ADDRESS": AssetType.IP,
            "IP": AssetType.IP,
            "WEB_APPLICATION": AssetType.WEB_APP,
            "WEB_APP": AssetType.WEB_APP,
            "URL": AssetType.API_ENDPOINT if "/api/" in host_val or "/rest/" in host_val else AssetType.WEB_APP,
            "SERVICE": AssetType.SERVICE,
        }
        asset_type = type_map.get(raw_type, AssetType.OTHER)

        # Parse services if present in metadata or fields
        discovered_services: List[DiscoveredService] = []
        if isinstance(raw.get("discovered_services"), list):
            for svc in raw["discovered_services"]:
                if isinstance(svc, dict) and "port" in svc:
                    discovered_services.append(
                        DiscoveredService(
                            port=int(svc["port"]),
                            protocol=str(svc.get("protocol", "tcp")),
                            service_name=svc.get("service_name"),
                            banner=svc.get("banner"),
                        )
                    )
        elif isinstance(raw.get("metadata"), dict) and "open_ports" in raw["metadata"]:
            for port in raw["metadata"]["open_ports"]:
                discovered_services.append(
                    DiscoveredService(port=int(port), protocol="tcp")
                )

        source = raw.get("source") or raw.get("source_type") or "osint_module"
        observed_at = cls.parse_datetime(raw.get("first_observed") or raw.get("observed_at"))

        return Asset(
            id=asset_id,
            assessment_id=assessment_id,
            hostname_or_address=host_val,
            asset_type=asset_type,
            discovered_services=discovered_services,
            source=source,
            observed_at=observed_at,
        )

    @classmethod
    def normalize_evidence(cls, raw: Dict[str, Any], fallback_assessment_id: str = "assess_unknown") -> Evidence:
        """
        Normalizes upstream evidence store records.
        Preserves cryptographic SHA-256 hashes, artifact locations, and raw dumps.
        """
        evidence_id = raw.get("evidence_id") or raw.get("id") or "evi_unknown"
        source = raw.get("tool_name") or raw.get("source") or raw.get("source_type") or "unknown_tool"

        # Build clear description
        desc = raw.get("description")
        if not desc and isinstance(raw.get("data"), dict):
            # Serialize concise snippet of structured data
            data_dict = raw["data"]
            desc = f"Evidence from {source}: " + ", ".join(f"{k}={v}" for k, v in list(data_dict.items())[:3])
        elif not desc:
            desc = f"Observation collected by {source}"

        observed_at = cls.parse_datetime(raw.get("collected_at") or raw.get("observed_at"))
        asset_id = raw.get("asset_id")
        ref_loc = raw.get("raw_payload_ref") or raw.get("reference_or_artifact_location")

        # Extract raw data representation
        raw_data = raw.get("raw_data")
        if not raw_data and isinstance(raw.get("data"), dict):
            import json
            raw_data = json.dumps(raw["data"], indent=2)

        return Evidence(
            id=evidence_id,
            source=source,
            description=desc,
            observed_at=observed_at,
            asset_id=asset_id,
            reference_or_artifact_location=ref_loc,
            raw_data=raw_data,
        )

    @classmethod
    def normalize_finding(cls, raw: Dict[str, Any], fallback_assessment_id: str = "assess_unknown") -> Finding:
        """
        Normalizes upstream scanner and OSINT findings into shared Finding contract.
        Handles Person 1 ('finding_id', 'evidence_ids', float 'confidence')
        and enforces zero-trust anti-upgrade constraints.
        """
        fid = raw.get("finding_id") or raw.get("id") or "find_unknown"
        assessment_id = raw.get("assessment_id") or fallback_assessment_id
        asset_id = raw.get("asset_id")
        title = raw.get("title") or "Untitled Finding"
        description = raw.get("description") or "No description recorded."

        # Severity mapping
        raw_sev = str(raw.get("severity", "")).upper()
        sev_map = {
            "CRITICAL": FindingSeverity.CRITICAL,
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
            "INFO": FindingSeverity.INFORMATIONAL,
            "INFORMATIONAL": FindingSeverity.INFORMATIONAL,
        }
        severity = sev_map.get(raw_sev, FindingSeverity.MEDIUM)

        # Confidence mapping (float or enum)
        raw_conf = raw.get("confidence")
        if isinstance(raw_conf, (int, float)):
            if raw_conf >= 0.8:
                confidence = ConfidenceLevel.HIGH
            elif raw_conf >= 0.5:
                confidence = ConfidenceLevel.MEDIUM
            else:
                confidence = ConfidenceLevel.LOW
        elif isinstance(raw_conf, str):
            c_upper = raw_conf.upper()
            if "HIGH" in c_upper:
                confidence = ConfidenceLevel.HIGH
            elif "LOW" in c_upper:
                confidence = ConfidenceLevel.LOW
            else:
                confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.MEDIUM

        # Verification Status mapping
        raw_ver = str(raw.get("verification_status", "")).upper()
        ver_map = {
            "CONFIRMED": VerificationStatus.CONFIRMED,
            "LIKELY": VerificationStatus.LIKELY,
            "UNVERIFIED": VerificationStatus.UNVERIFIED,
            "FALSE_POSITIVE": VerificationStatus.FALSE_POSITIVE,
        }
        verification_status = ver_map.get(raw_ver, VerificationStatus.UNVERIFIED)

        # Supporting evidence IDs
        ev_refs = raw.get("evidence_references") or raw.get("evidence_ids") or []
        if isinstance(ev_refs, str):
            ev_refs = [ev_refs]
        evidence_references = [str(x) for x in ev_refs if str(x).strip()]

        # Enforce contract integrity: Cannot be CONFIRMED with zero evidence
        if verification_status == VerificationStatus.CONFIRMED and not evidence_references:
            logger.warning(f"Finding {fid} claimed CONFIRMED without evidence. Demoting to UNVERIFIED.")
            verification_status = VerificationStatus.UNVERIFIED
            confidence = ConfidenceLevel.LOW

        remediation = raw.get("remediation")
        source_tool = raw.get("source_tool") or raw.get("tool_name") or "security_scanner"
        cve = raw.get("cve")
        cwe = raw.get("cwe")
        first_seen = cls.parse_datetime(raw.get("first_seen"))
        last_seen = cls.parse_datetime(raw.get("last_seen") or raw.get("first_seen"))

        return Finding(
            id=fid,
            assessment_id=assessment_id,
            asset_id=asset_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            verification_status=verification_status,
            evidence_references=evidence_references,
            remediation=remediation,
            source_tool=source_tool,
            cve=cve,
            cwe=cwe,
            first_seen=first_seen,
            last_seen=last_seen,
        )


class UpstreamAssessmentClient:
    """
    HTTP client communicating with Person 1's orchestrator and Person 2's scanner backend.
    Gracefully handles disconnected services, timeout errors, and partial responses.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_health(self) -> Dict[str, Any]:
        """
        Polls backend health status.
        Returns honest status: 'connected', 'pending', or 'not_connected'.
        """
        import httpx
        try:
            r = httpx.get(f"{self.base_url}/health", timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                return {
                    "status": "connected",
                    "module": data.get("service", "AegisPT Backend"),
                    "details": data,
                }
            return {
                "status": "failed",
                "module": "Backend API",
                "details": f"HTTP {r.status_code}",
            }
        except Exception as e:
            return {
                "status": "not_connected",
                "module": "Backend API",
                "details": str(e),
            }

    def fetch_assessment_data(
        self, assessment_id: str
    ) -> Tuple[Optional[Assessment], List[Asset], List[Finding], List[Evidence], Dict[str, str]]:
        """
        Retrieves all available results for an assessment from upstream endpoints.
        Returns: (assessment, assets, findings, evidence, module_statuses)
        """
        import httpx

        module_statuses: Dict[str, str] = {
            "orchestrator": "not_connected",
            "osint": "not_connected",
            "scanners": "not_connected",
        }

        try:
            with httpx.Client(base_url=self.base_url, timeout=self.timeout) as client:
                # 1. Fetch assessment record
                r_assess = client.get(f"/assessments/{assessment_id}")
                if r_assess.status_code != 200:
                    return None, [], [], [], module_statuses
                
                module_statuses["orchestrator"] = "connected"
                assessment = UpstreamNormalizer.normalize_assessment(r_assess.json())

                # 2. Fetch assets
                assets: List[Asset] = []
                r_assets = client.get(f"/assessments/{assessment_id}/assets")
                if r_assets.status_code == 200:
                    module_statuses["osint"] = "connected"
                    for raw_a in r_assets.json():
                        assets.append(UpstreamNormalizer.normalize_asset(raw_a, assessment_id))
                else:
                    module_statuses["osint"] = "failed"

                # 3. Fetch evidence
                evidence: List[Evidence] = []
                r_evi = client.get(f"/assessments/{assessment_id}/evidence")
                if r_evi.status_code == 200:
                    for raw_e in r_evi.json():
                        evidence.append(UpstreamNormalizer.normalize_evidence(raw_e, assessment_id))

                # 4. Fetch findings
                findings: List[Finding] = []
                r_fnd = client.get(f"/assessments/{assessment_id}/findings")
                if r_fnd.status_code == 200:
                    module_statuses["scanners"] = "connected"
                    for raw_f in r_fnd.json():
                        findings.append(UpstreamNormalizer.normalize_finding(raw_f, assessment_id))
                else:
                    module_statuses["scanners"] = "pending"

                return assessment, assets, findings, evidence, module_statuses

        except Exception as e:
            logger.warning(f"Upstream communication failure for {assessment_id}: {str(e)}")
            return None, [], [], [], module_statuses
