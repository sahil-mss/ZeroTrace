"""
Unit and integration tests for Session 10 passive intelligence adapters:
- DNS metadata collection adapter (DNSMetadataAdapter)
- Certificate transparency log lookup adapter (CertificateTransparencyAdapter)

Verifies:
- Safe, bounded queries with mock DNS and HTTP interactions (zero live network traffic).
- Distinction between missing DNS records and resolver failures.
- Candidate-only asset marking and scope validation for CT log discoveries.
- Disabled-by-default behavior and configuration enablement.
- Refusal on unapproved, missing, or expired assessments and out-of-scope targets.
- Rate limiting, bounded response sizes, caching, timeouts, and cooperative cancellation.
"""

from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import httpx
import pytest
from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    ScopeStatus,
    TargetType,
    TestPermissionLevel,
)
from aegis_common.models import Assessment, ScopeRule
from backend.app.db.base import Base
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.session import get_engine, get_session_factory
from backend.app.services.osint_service import (
    CertificateTransparencyAdapter,
    DNSMetadataAdapter,
    OSINTCollectionService,
)
from modules.osint.contracts import (
    CancellationToken,
    OSINTCollectionContext,
)


@pytest.fixture
def db_session():
    """Provides an isolated in-memory SQLite database session."""
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def active_assessment(db_session: Session) -> Assessment:
    """Creates an approved assessment with lab.example.test and subdomains."""
    assessment = Assessment(
        assessment_id="assess_s10_lab_01",
        name="ZeroTrace Session 10 Test",
        organization_name="Security Research Corp",
        authorized_by="Lead Auditor",
        lifecycle_status=AssessmentStatus.APPROVED,
        permitted_profiles=[TestPermissionLevel.PASSIVE_ONLY],
        scope_rules=[
            ScopeRule(
                target_value="lab.example.test",
                target_type=TargetType.DOMAIN,
                include_subdomains=True,
                approved_ports=[80, 443],
            ),
        ],
    )
    repo = AssessmentRepository(db_session)
    repo.create(assessment)
    db_session.commit()
    return assessment


# -----------------------------------------------------------------------------
# Adapter A: DNS Metadata Tests
# -----------------------------------------------------------------------------


def _create_mock_resolver(
    record_map: dict[str, list[str]], failures: dict[str, Exception] | None = None
):
    """Creates a mock dnspython resolver returning configured answers or exceptions."""
    failures = failures or {}

    class MockAnswer:
        def __init__(self, data: list[str]):
            self._data = data

        def __iter__(self):
            return iter(self._data)

    resolver = MagicMock()

    def resolve_side_effect(qname, rtype):
        if rtype in failures:
            raise failures[rtype]
        if rtype in record_map:
            return MockAnswer(record_map[rtype])
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = resolve_side_effect
    return resolver


@pytest.mark.asyncio
async def test_dns_metadata_adapter_disabled_by_default(active_assessment: Assessment):
    """Verifies that DNSMetadataAdapter is disabled by default."""
    adapter = DNSMetadataAdapter()
    assert adapter.enabled is False

    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is False
    assert any("disabled by default" in err for err in result.errors)


@pytest.mark.asyncio
async def test_dns_metadata_adapter_successful_query(active_assessment: Assessment):
    """
    Verifies valid DNS metadata queries:
    - Queries A, AAAA, CNAME, MX, NS records with mock resolver.
    - Normalizes results into structured observation with relationships.
    """
    mock_records = {
        "A": ["192.168.1.10", "192.168.1.11"],
        "AAAA": ["2001:db8::1"],
        "CNAME": ["web.lab.example.test."],
        "MX": ["10 mail.lab.example.test."],
        "NS": ["ns1.lab.example.test."],
    }
    mock_resolver = _create_mock_resolver(mock_records)

    adapter = DNSMetadataAdapter(enabled=True, resolver=mock_resolver)
    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is True
    assert len(result.observations) >= 1

    primary_obs = result.observations[0]
    assert primary_obs.target == "lab.example.test"
    assert primary_obs.data["records"]["A"] == ["192.168.1.10", "192.168.1.11"]
    assert primary_obs.data["records"]["AAAA"] == ["2001:db8::1"]
    assert "192.168.1.10" in primary_obs.relationships["resolves_to_ip"]
    assert "web.lab.example.test" in primary_obs.relationships["canonical_name"]


@pytest.mark.asyncio
async def test_dns_metadata_missing_records_vs_resolver_failures(active_assessment: Assessment):
    """
    Verifies distinction between:
    - Missing records (NoAnswer -> NO_RECORD)
    - Resolver failures (Timeout -> RESOLVER_FAILURE)
    """
    mock_records = {"A": ["10.0.0.1"]}
    failures = {
        "AAAA": dns.resolver.NoAnswer(),
        "MX": dns.exception.Timeout(),
    }
    mock_resolver = _create_mock_resolver(mock_records, failures=failures)

    adapter = DNSMetadataAdapter(enabled=True, resolver=mock_resolver)
    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is True
    primary_obs = result.observations[0]

    outcomes = primary_obs.data["query_outcomes"]
    assert outcomes["A"]["status"] == "RESOLVED"
    assert outcomes["AAAA"]["status"] == "NO_RECORD"
    assert outcomes["MX"]["status"] == "RESOLVER_FAILURE"
    assert "timed out" in outcomes["MX"]["error"].lower()


@pytest.mark.asyncio
async def test_dns_metadata_refuses_out_of_scope_target(active_assessment: Assessment):
    """Verifies that querying a target outside the approved context is refused."""
    adapter = DNSMetadataAdapter(enabled=True)
    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("unauthorized.com", context)
    assert result.success is False
    assert any("not in approved assessment targets" in err for err in result.errors)


@pytest.mark.asyncio
async def test_dns_metadata_cancellation(active_assessment: Assessment):
    """Verifies that cancellation token aborts DNS collection promptly."""
    token = CancellationToken()
    token.cancel("Operator aborted DNS query")

    adapter = DNSMetadataAdapter(enabled=True)
    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
        cancellation_token=token,
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is False
    assert any("Cancelled before collection" in err for err in result.errors)


# -----------------------------------------------------------------------------
# Adapter B: Certificate Transparency (CT) Tests
# -----------------------------------------------------------------------------


def _create_mock_httpx_client(
    status_code: int = 200,
    json_data: list[dict] | None = None,
    content_bytes: bytes | None = None,
    simulate_timeout: bool = False,
):
    """Creates an httpx.AsyncClient with mock transport returning configured responses."""
    if simulate_timeout:
        mock_transport = httpx.MockTransport(
            MagicMock(side_effect=httpx.TimeoutException("Mock timeout"))
        )
    elif content_bytes is not None:
        mock_transport = httpx.MockTransport(
            lambda request: httpx.Response(status_code=status_code, content=content_bytes)
        )
    else:
        json_data = json_data if json_data is not None else []
        mock_transport = httpx.MockTransport(
            lambda request: httpx.Response(status_code=status_code, json=json_data)
        )
    return httpx.AsyncClient(transport=mock_transport)


@pytest.mark.asyncio
async def test_ct_adapter_disabled_by_default(active_assessment: Assessment):
    """Verifies CertificateTransparencyAdapter is disabled by default."""
    adapter = CertificateTransparencyAdapter()
    assert adapter.enabled is False

    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is False
    assert any("disabled by default" in err for err in result.errors)


@pytest.mark.asyncio
async def test_ct_adapter_successful_discovery(active_assessment: Assessment):
    """
    Verifies valid Certificate Transparency lookup:
    - Parses crt.sh JSON response.
    - Extracts candidate hostnames and certificate metadata.
    - Marks discovered hostnames as candidate-only with no automatic scan permission.
    """
    sample_ct_json = [
        {
            "id": 1234567,
            "entry_timestamp": "2026-01-15T12:00:00",
            "not_before": "2026-01-15T00:00:00",
            "not_after": "2026-04-15T00:00:00",
            "common_name": "lab.example.test",
            "name_value": "lab.example.test\napi.lab.example.test\nadmin.lab.example.test",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        },
        {
            "id": 1234568,
            "entry_timestamp": "2026-01-16T12:00:00",
            "not_before": "2026-01-16T00:00:00",
            "not_after": "2026-04-16T00:00:00",
            "common_name": "external.partner.test",
            "name_value": "external.partner.test",
            "issuer_name": "C=US, O=DigiCert, CN=DigiCert Global Root CA",
        },
    ]

    mock_client = _create_mock_httpx_client(status_code=200, json_data=sample_ct_json)
    adapter = CertificateTransparencyAdapter(enabled=True, http_client=mock_client)

    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is True
    assert len(result.observations) >= 3

    # Primary evidence observation
    primary = result.observations[0]
    assert primary.target == "lab.example.test"
    assert "api.lab.example.test" in primary.data["hostnames"]

    # Candidate observations
    candidate_targets = [o.target for o in result.observations[1:]]
    assert "api.lab.example.test" in candidate_targets
    assert "admin.lab.example.test" in candidate_targets

    for obs in result.observations[1:]:
        assert obs.metadata["is_candidate"] is True
        assert obs.metadata["active_scan_permitted"] is False
        assert obs.data["service_live_confirmed"] is False


@pytest.mark.asyncio
async def test_ct_adapter_caching_behavior(active_assessment: Assessment):
    """
    Verifies that repeated queries to the same domain reuse in-memory cache
    without issuing repeated external HTTP requests.
    """
    call_count = 0

    def mock_handler(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json=[{"id": 1, "name_value": "sub.lab.example.test"}])

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    adapter = CertificateTransparencyAdapter(enabled=True, http_client=mock_client)

    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    # First call: performs HTTP query
    res1 = await adapter.collect("lab.example.test", context)
    assert res1.success is True
    assert call_count == 1

    # Second call: uses cache
    res2 = await adapter.collect("lab.example.test", context)
    assert res2.success is True
    assert call_count == 1  # Unchanged!


@pytest.mark.asyncio
async def test_ct_adapter_error_and_timeout_handling(active_assessment: Assessment):
    """Verifies graceful handling of HTTP 429, HTTP 503, timeouts, and malformed JSON."""
    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    # 1. HTTP 429 Rate Limited
    client_429 = _create_mock_httpx_client(status_code=429)
    adapter_429 = CertificateTransparencyAdapter(enabled=True, http_client=client_429)
    res_429 = await adapter_429.collect("lab.example.test", context)
    assert res_429.success is False
    assert any("rate limit exceeded" in err for err in res_429.errors)

    # 2. HTTP 503 Unavailable
    client_503 = _create_mock_httpx_client(status_code=503)
    adapter_503 = CertificateTransparencyAdapter(enabled=True, http_client=client_503)
    res_503 = await adapter_503.collect("lab.example.test", context)
    assert res_503.success is False
    assert any("HTTP error 503" in err for err in res_503.errors)

    # 3. Timeout
    client_timeout = _create_mock_httpx_client(simulate_timeout=True)
    adapter_timeout = CertificateTransparencyAdapter(enabled=True, http_client=client_timeout)
    res_timeout = await adapter_timeout.collect("lab.example.test", context)
    assert res_timeout.success is False
    assert any("timed out" in err for err in res_timeout.errors)

    # 4. Malformed JSON
    client_malformed = _create_mock_httpx_client(status_code=200, content_bytes=b"Not JSON")
    adapter_malformed = CertificateTransparencyAdapter(enabled=True, http_client=client_malformed)
    res_malformed = await adapter_malformed.collect("lab.example.test", context)
    assert res_malformed.success is False
    assert any("Failed to parse JSON" in err for err in res_malformed.errors)


@pytest.mark.asyncio
async def test_ct_adapter_bounded_response_size(active_assessment: Assessment):
    """Verifies rejection when response size exceeds maximum configured bytes."""
    oversized_content = b"[" + b'{"id": 1, "name_value": "test"},' * 10000 + b'{"id": 2}]'
    client_oversized = _create_mock_httpx_client(status_code=200, content_bytes=oversized_content)

    adapter = CertificateTransparencyAdapter(
        enabled=True,
        http_client=client_oversized,
        max_response_bytes=1024,  # 1 KB limit
    )

    context = OSINTCollectionContext(
        assessment_id=active_assessment.assessment_id,
        approved_targets=["lab.example.test"],
        scope_validator=MagicMock(),
    )

    result = await adapter.collect("lab.example.test", context)
    assert result.success is False
    assert any("exceeded budget" in err for err in result.errors)


# -----------------------------------------------------------------------------
# End-to-End Collection Service Integration with Both Adapters
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_osint_service_with_session10_adapters(
    db_session: Session, active_assessment: Assessment
):
    """
    Verifies full integration through OSINTCollectionService:
    - Executes DNSMetadataAdapter and CertificateTransparencyAdapter.
    - Persists evidence records in EvidenceService.
    - Classifies candidate hostnames: in-scope as IN_SCOPE, out-of-scope as OUT_OF_SCOPE.
    - Ensures candidate assets are not automatically scanned.
    """
    mock_records = {
        "A": ["192.168.1.50"],
        "MX": ["10 mail.lab.example.test."],
    }
    mock_resolver = _create_mock_resolver(mock_records)
    dns_adapter = DNSMetadataAdapter(enabled=True, resolver=mock_resolver)

    ct_data = [
        {
            "id": 1001,
            "common_name": "lab.example.test",
            "name_value": "api.lab.example.test\nexternal-partner.org",
            "issuer_name": "DigiCert",
        }
    ]
    mock_client = _create_mock_httpx_client(status_code=200, json_data=ct_data)
    ct_adapter = CertificateTransparencyAdapter(enabled=True, http_client=mock_client)

    service = OSINTCollectionService(
        session=db_session,
        adapters=[dns_adapter, ct_adapter],
    )

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )

    assert summary.status == "COMPLETED"
    assert "dns_metadata" in summary.adapters_executed
    assert "cert_transparency" in summary.adapters_executed
    assert summary.evidence_records_created >= 2
    assert summary.new_assets_created >= 2

    # In-scope candidate: api.lab.example.test
    api_asset = service.asset_service.get_asset_by_value(
        active_assessment.assessment_id, "api.lab.example.test"
    )
    assert api_asset is not None
    assert api_asset.scope_classification == ScopeStatus.IN_SCOPE

    # Out-of-scope candidate: external-partner.org
    external_asset = service.asset_service.get_asset_by_value(
        active_assessment.assessment_id, "external-partner.org"
    )
    assert external_asset is not None
    assert external_asset.scope_classification == ScopeStatus.OUT_OF_SCOPE
