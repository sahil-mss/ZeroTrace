from typing import Any

import httpx

from backend.policy.scope_validator import ScopeValidator
from backend.storage.evidence_store import EvidenceStore
from schemas.enums import EvidenceSourceType


class CertTransparencyAdapter:
    """
    Passive Certificate Transparency (CT) Log Intelligence Adapter.
    Queries public CT logs (via crt.sh) to discover issued certificates and subdomains.
    """

    CRTSH_URL = "https://crt.sh/"

    def __init__(self, evidence_store: EvidenceStore, timeout_seconds: float = 10.0):
        self.evidence_store = evidence_store
        self.timeout = timeout_seconds

    async def query(self, assessment_id: str, target: str) -> dict[str, Any]:
        """
        Queries CT logs for certificates matching %.domain.
        Returns unique discovered subdomains and cryptographic evidence.
        """
        canon = ScopeValidator.canonicalize(target)
        domain = canon["hostname"]

        discovered_names: set[str] = set()
        raw_response_bytes = b""
        query_success = False
        error_msg = None

        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": "AegisPT-PassiveRecon/1.0 (+https://github.com/aegispt)"}

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

        # Package raw response or error into Evidence
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
