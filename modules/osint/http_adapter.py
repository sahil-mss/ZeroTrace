from typing import Any

import httpx

from backend.policy.scope_validator import ScopeValidator
from backend.storage.evidence_store import EvidenceStore
from schemas.enums import EvidenceSourceType


class HttpFingerprintAdapter:
    """
    Passive/Low-Impact HTTP Intelligence & Header Inspection Adapter.
    Performs standard HTTP/HTTPS probes to collect technology banners,
    security headers (HSTS, CSP, X-Frame-Options), and cookie attributes.
    """

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    def __init__(self, evidence_store: EvidenceStore, timeout_seconds: float = 6.0):
        self.evidence_store = evidence_store
        self.timeout = timeout_seconds

    async def probe(self, assessment_id: str, target: str) -> dict[str, Any]:
        """
        Safely probes target using HEAD / GET requests.
        Collects response headers, redirects, and missing security controls.
        """
        canon = ScopeValidator.canonicalize(target)
        hostname = canon["hostname"]
        port = canon["port"]
        scheme = canon["scheme"] or "http"

        if port:
            url = f"{scheme}://{hostname}:{port}/"
        else:
            url = f"{scheme}://{hostname}/"

        observed_headers: dict[str, str] = {}
        status_code = None
        server_banner = None
        x_powered_by = None
        missing_sec_headers: list[str] = []
        present_sec_headers: dict[str, str] = {}
        cookies: list[dict[str, Any]] = []
        error_msg = None

        headers = {"User-Agent": "AegisPT-Audit/1.0 (+security-audit)"}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,  # Allow self-signed certs in controlled lab environments
            ) as client:
                resp = await client.get(url, headers=headers)
                status_code = resp.status_code
                observed_headers = dict(resp.headers)

                # Extract tech fingerprints
                server_banner = resp.headers.get("server")
                x_powered_by = resp.headers.get("x-powered-by")

                # Check security headers
                lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                for sec_h in self.SECURITY_HEADERS:
                    if sec_h in lower_headers:
                        present_sec_headers[sec_h] = lower_headers[sec_h]
                    else:
                        missing_sec_headers.append(sec_h)

                # Check cookies
                for c in resp.cookies.jar:
                    cookies.append(
                        {
                            "name": c.name,
                            "secure": c.secure,
                            "httponly": bool(
                                c.has_nonstandard_attr("httponly") or getattr(c, "httponly", False)
                            ),
                            "path": c.path,
                            "domain": c.domain,
                        }
                    )

        except httpx.ConnectError:
            error_msg = f"Failed to connect to {url}"
        except httpx.TimeoutException:
            error_msg = f"Connection to {url} timed out"
        except Exception as e:
            error_msg = f"HTTP probe error: {str(e)}"

        # Package into verifiable Evidence
        evidence_data = {
            "probe_url": url,
            "status_code": status_code,
            "server_banner": server_banner,
            "x_powered_by": x_powered_by,
            "present_security_headers": present_sec_headers,
            "missing_security_headers": missing_sec_headers,
            "cookies": cookies,
            "raw_headers": observed_headers,
            "error": error_msg,
        }

        evidence = self.evidence_store.create_evidence(
            assessment_id=assessment_id,
            source_type=EvidenceSourceType.HTTP_FINGERPRINT,
            tool_name="HttpFingerprintAdapter",
            tool_version="1.0",
            data=evidence_data,
            metadata={"target_url": url, "status_code": status_code},
        )

        return {
            "url": url,
            "status_code": status_code,
            "server": server_banner,
            "x_powered_by": x_powered_by,
            "missing_security_headers": missing_sec_headers,
            "present_security_headers": present_sec_headers,
            "cookies": cookies,
            "evidence": evidence,
            "error": error_msg,
        }
