import tempfile
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    EvidenceSourceType,
    ScopeStatus,
    TargetType,
)
from aegis_common.models import Assessment, ScopeRule
from backend.app.db.base import Base
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.session import get_engine, get_session_factory
from backend.app.services.asset_service import AssetObservation, AssetService
from backend.app.services.evidence_service import (
    EvidenceObservation,
    EvidenceService,
    LocalFilesystemEvidenceStorage,
)
from backend.app.services.normalization import (
    calculate_content_hash,
    canonical_json_dumps,
    clean_whitespace,
    normalize_hostname,
    normalize_ip_address,
    normalize_url,
)


@pytest.fixture
def db_session():
    """Provides a fresh isolated in-memory/temp SQLite database session for testing."""
    db_file = tempfile.mktemp(suffix=".db")
    engine = get_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def test_assessment(db_session: Session) -> Assessment:
    """Creates a sample active assessment with explicit scope rules."""
    assessment = Assessment(
        assessment_id="assess_test_norm_01",
        name="Normalization and Registry Test",
        organization_name="Security Research Lab",
        authorized_by="Lead Security Architect",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[
            ScopeRule(
                target_value="api.example.test",
                target_type=TargetType.DOMAIN,
                include_subdomains=False,
                approved_ports=[80, 443],
                permitted_path_prefixes=["/api"],
            ),
            ScopeRule(
                target_value="*.sub.example.test",
                target_type=TargetType.DOMAIN,
                include_subdomains=True,
                approved_ports=[80, 443, 8080],
            ),
            ScopeRule(
                target_value="192.168.1.10",
                target_type=TargetType.IP_ADDRESS,
                approved_ports=[80, 443],
            ),
        ],
    )
    repo = AssessmentRepository(db_session)
    repo.create(assessment)
    db_session.commit()
    return assessment


# -----------------------------------------------------------------------------
# Part A: Normalization Utilities Tests
# -----------------------------------------------------------------------------


def test_hostname_normalization():
    # Lowercase, whitespace, and trailing dot
    assert normalize_hostname("  Example.Test.  ") == "example.test"
    assert normalize_hostname("SUB.DOMAIN.EXAMPLE.TEST...") == "sub.domain.example.test"

    # Internationalized Domain Name (IDN / Punycode)
    assert normalize_hostname("münchen.de") == "xn--mnchen-3ya.de"
    assert normalize_hostname("räksmörgås.josefsson.org") == "xn--rksmrgs-5wao1o.josefsson.org"

    # Rejection of invalid hostnames
    with pytest.raises(ValueError, match="empty"):
        normalize_hostname("   ")

    with pytest.raises(ValueError, match="Invalid character"):
        normalize_hostname("host name.test")

    with pytest.raises(ValueError, match="Invalid character"):
        normalize_hostname("host/path")

    with pytest.raises(ValueError, match="Invalid character"):
        normalize_hostname("user@host")


def test_ip_address_normalization():
    # IPv4 whitespace
    assert normalize_ip_address("  192.168.1.1  ") == "192.168.1.1"

    # IPv6 compression and bracket stripping
    assert normalize_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ip_address("[2001:db8::1]") == "2001:db8::1"
    assert normalize_ip_address("::1") == "::1"

    # Invalid IP addresses
    with pytest.raises(ValueError, match="Invalid IPv4 or IPv6"):
        normalize_ip_address("999.999.999.999")

    with pytest.raises(ValueError, match="Invalid IPv4 or IPv6"):
        normalize_ip_address("not_an_ip")


def test_url_normalization():
    # Default port standardizing
    assert normalize_url("HTTP://Example.Test:80/api/v1") == "http://example.test/api/v1"
    assert normalize_url("https://example.test:443/login") == "https://example.test/login"

    # Non-default port must NOT be stripped (distinguishes resources)
    assert normalize_url("http://example.test:8080/api") == "http://example.test:8080/api"
    assert normalize_url("https://example.test:8443/admin") == "https://example.test:8443/admin"

    # Path traversal normalization and trailing slash preservation
    assert (
        normalize_url("https://example.test/api/v1/../../etc/passwd")
        == "https://example.test/etc/passwd"
    )
    assert normalize_url("https://example.test/api/v1/../v2/") == "https://example.test/api/v2/"

    # Query parameters canonical sorting
    url_sorted = normalize_url("https://example.test/search?b=2&a=1&c=3")
    assert url_sorted == "https://example.test/search?a=1&b=2&c=3"

    # Credentials must be rejected
    with pytest.raises(ValueError, match="embedded credentials"):
        normalize_url("https://admin:secret123@example.test/dashboard")

    # Unsupported schemes rejected
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        normalize_url("ftp://example.test/file.txt")


def test_canonical_json_and_stable_hashing():
    # Two dictionaries with identical keys/values in different order
    dict1 = {"b": 2, "a": 1, "nested": {"y": "val", "x": 10}}
    dict2 = {"nested": {"x": 10, "y": "val"}, "a": 1, "b": 2}

    json1 = canonical_json_dumps(dict1)
    json2 = canonical_json_dumps(dict2)
    assert json1 == json2

    hash1 = calculate_content_hash(dict1)
    hash2 = calculate_content_hash(dict2)
    assert hash1 == hash2
    assert len(hash1) == 64

    # Whitespace normalization
    assert clean_whitespace("   hello    world  \t  ") == "hello world"


# -----------------------------------------------------------------------------
# Part B: Evidence Service Tests
# -----------------------------------------------------------------------------


def test_evidence_ingestion_and_idempotent_deduplication(
    db_session: Session, test_assessment: Assessment
):
    evidence_service = EvidenceService(session=db_session)

    obs = EvidenceObservation(
        assessment_id=test_assessment.assessment_id,
        source_name="nmap_scanner",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        collection_method="AUTOMATED_PROBE",
        data={"port": 443, "service": "https", "state": "open"},
        metadata={"tool": "nmap", "scan_args": "-sV -p 443"},
        sanitized_excerpt="Discovered open port 443/tcp https on target.",
    )

    # 1. First ingestion -> new record
    evi1, is_new1 = evidence_service.ingest_observation(obs)
    assert is_new1 is True
    assert evi1.evidence_id is not None
    assert evi1.content_hash is not None
    assert evidence_service.verify_evidence_integrity(evi1.evidence_id) is True

    # 2. Repeated identical observation from the same source -> idempotent deduplication
    evi2, is_new2 = evidence_service.ingest_observation(obs)
    assert is_new2 is False
    assert evi2.evidence_id == evi1.evidence_id
    assert evi2.content_hash == evi1.content_hash

    # Verify database has exactly 1 evidence row
    records = evidence_service.list_by_assessment(test_assessment.assessment_id)
    assert len(records) == 1

    # 3. Materially different observation from the same source -> creates new distinct record
    obs_changed = EvidenceObservation(
        assessment_id=test_assessment.assessment_id,
        source_name="nmap_scanner",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        data={"port": 8080, "service": "http-proxy", "state": "open"},
    )
    evi3, is_new3 = evidence_service.ingest_observation(obs_changed)
    assert is_new3 is True
    assert evi3.evidence_id != evi1.evidence_id
    assert evi3.content_hash != evi1.content_hash

    records_after = evidence_service.list_by_assessment(test_assessment.assessment_id)
    assert len(records_after) == 2


def test_evidence_invalid_assessment_reference(db_session: Session):
    evidence_service = EvidenceService(session=db_session)
    bad_obs = EvidenceObservation(
        assessment_id="assess_does_not_exist_999",
        source_name="osint_shodan",
        source_type=EvidenceSourceType.DNS_LOOKUP,
        data={"ip": "1.2.3.4"},
    )

    with pytest.raises(ValueError, match="does not exist"):
        evidence_service.ingest_observation(bad_obs)


def test_evidence_cross_assessment_violation(db_session: Session, test_assessment: Assessment):
    # Create a second assessment and an asset in it
    repo = AssessmentRepository(db_session)
    other_assessment = repo.create(
        Assessment(
            assessment_id="assess_other_99",
            name="Other Assessment",
            organization_name="Other Org",
            authorized_by="Other Lead",
            lifecycle_status=AssessmentStatus.APPROVED,
        )
    )
    db_session.commit()

    asset_service = AssetService(session=db_session)
    asset_in_other, _ = asset_service.register_asset(
        AssetObservation(
            assessment_id=other_assessment.assessment_id,
            raw_value="other.example.test",
        )
    )
    db_session.commit()

    # Try to ingest evidence for test_assessment referencing asset_in_other -> must fail
    evidence_service = EvidenceService(session=db_session)
    cross_obs = EvidenceObservation(
        assessment_id=test_assessment.assessment_id,
        source_name="test_tool",
        source_type=EvidenceSourceType.DNS_LOOKUP,
        asset_id=asset_in_other.asset_id,
        data={"finding": "leaked info"},
    )

    with pytest.raises(ValueError, match="Cross-assessment boundary violation"):
        evidence_service.ingest_observation(cross_obs)


def test_evidence_sanitization_and_ai_separation(db_session: Session, test_assessment: Assessment):
    evidence_service = EvidenceService(session=db_session)

    # Observation containing secrets and AI interpretations
    obs = EvidenceObservation(
        assessment_id=test_assessment.assessment_id,
        source_name="http_interceptor",
        source_type=EvidenceSourceType.HTTP_FINGERPRINT,
        data={
            "endpoint": "/api/v1/auth",
            "password": "SuperSecretPassword123!",
            "api_key": "live_key_999888777",
            "user": "alice",
        },
        sanitized_excerpt="Response header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token body: password=SuperSecretPassword123!",
        ai_interpretation={
            "model": "gemini-1.5-pro",
            "conclusion": "Likely insecure token handling.",
            "confidence": 0.85,
        },
    )

    evi, _ = evidence_service.ingest_observation(obs)

    # 1. Verify secrets in data are redacted
    assert evi.data["password"] == "[REDACTED]"
    assert evi.data["api_key"] == "[REDACTED]"
    assert evi.data["user"] == "alice"

    # 2. Verify text excerpt scrubbing
    assert "SuperSecretPassword123!" not in evi.sanitized_excerpt
    assert "[REDACTED]" in evi.sanitized_excerpt

    # 3. Verify AI interpretation is kept separate in metadata and not polluting raw facts
    assert "ai_analysis" in evi.metadata
    assert evi.metadata["ai_analysis"]["conclusion"] == "Likely insecure token handling."
    assert "model" not in evi.data


def test_raw_blob_evidence_storage(db_session: Session, test_assessment: Assessment):
    temp_dir = tempfile.mkdtemp()
    storage = LocalFilesystemEvidenceStorage(base_dir=temp_dir)
    evidence_service = EvidenceService(session=db_session, raw_storage=storage)

    raw_payload = b"GET /admin HTTP/1.1\r\nHost: api.example.test\r\n\r\n"
    obs = EvidenceObservation(
        assessment_id=test_assessment.assessment_id,
        source_name="raw_probe",
        source_type=EvidenceSourceType.HTTP_FINGERPRINT,
        data={"method": "GET", "url": "/admin"},
        raw_payload=raw_payload,
    )

    evi, is_new = evidence_service.ingest_observation(obs)
    assert is_new is True
    assert evi.raw_payload_ref is not None

    # Retrieve through raw storage extension point
    retrieved = storage.retrieve_raw(evi.raw_payload_ref)
    assert retrieved == raw_payload


# -----------------------------------------------------------------------------
# Part C & D: Asset Registry & Data Integrity Tests
# -----------------------------------------------------------------------------


def test_asset_registration_and_scope_classification(
    db_session: Session, test_assessment: Assessment
):
    asset_service = AssetService(session=db_session)

    # 1. In-scope target -> IN_SCOPE
    in_scope_obs = AssetObservation(
        assessment_id=test_assessment.assessment_id,
        raw_value="  api.example.test  ",
    )
    asset1, is_new1 = asset_service.register_asset(in_scope_obs)
    assert is_new1 is True
    assert asset1.normalized_value == "api.example.test"
    assert asset1.scope_classification == ScopeStatus.IN_SCOPE

    # 2. Out-of-scope target -> OUT_OF_SCOPE
    out_scope_obs = AssetObservation(
        assessment_id=test_assessment.assessment_id,
        raw_value="unauthorized-evil.com",
    )
    asset2, is_new2 = asset_service.register_asset(out_scope_obs)
    assert is_new2 is True
    assert asset2.normalized_value == "unauthorized-evil.com"
    assert asset2.scope_classification == ScopeStatus.OUT_OF_SCOPE


def test_out_of_scope_asset_never_upgraded_by_later_observation(
    db_session: Session, test_assessment: Assessment
):
    asset_service = AssetService(session=db_session)

    # 1. Register an out-of-scope asset
    obs1 = AssetObservation(
        assessment_id=test_assessment.assessment_id,
        raw_value="unauthorized.test",
        confidence=0.5,
    )
    asset1, is_new1 = asset_service.register_asset(obs1)
    assert is_new1 is True
    assert asset1.scope_classification == ScopeStatus.OUT_OF_SCOPE

    # 2. Later observation from an authorized tool claiming high confidence or trying to upgrade
    obs2 = AssetObservation(
        assessment_id=test_assessment.assessment_id,
        raw_value="  UNAUTHORIZED.TEST.  ",
        confidence=1.0,
        metadata={"reported_by": "high_trust_scanner"},
    )
    asset2, is_new2 = asset_service.register_asset(obs2)
    assert is_new2 is False
    assert asset2.asset_id == asset1.asset_id
    # Must remain OUT_OF_SCOPE! Never auto-upgrade!
    assert asset2.scope_classification == ScopeStatus.OUT_OF_SCOPE
    assert asset2.confidence == 1.0


def test_asset_deduplication_and_timestamp_updates(
    db_session: Session, test_assessment: Assessment
):
    asset_service = AssetService(session=db_session)

    t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 1, 2, 15, 30, 0, tzinfo=UTC)

    obs1 = AssetObservation(
        assessment_id=test_assessment.assessment_id,
        raw_value="api.example.test",
        observed_at=t1,
        relationships={"parent": ["example.test"]},
    )
    asset1, is_new1 = asset_service.register_asset(obs1)
    assert is_new1 is True
    assert asset1.first_seen == t1
    assert asset1.last_seen == t1

    # Second observation with updated timestamp and additional relationship
    obs2 = AssetObservation(
        assessment_id=test_assessment.assessment_id,
        raw_value="api.example.test.",
        observed_at=t2,
        relationships={"service": ["https"]},
    )
    asset2, is_new2 = asset_service.register_asset(obs2)
    assert is_new2 is False
    assert asset2.asset_id == asset1.asset_id
    assert asset2.first_seen == t1  # First seen preserved
    assert asset2.last_seen == t2  # Last seen updated

    # Merged relationships
    assert "parent" in asset2.relationships
    assert "service" in asset2.relationships

    # Verify only 1 asset record in assessment
    assets = asset_service.list_assets(test_assessment.assessment_id)
    assert len(assets) == 1


def test_asset_assessment_isolation(db_session: Session, test_assessment: Assessment):
    repo = AssessmentRepository(db_session)
    other_assessment = repo.create(
        Assessment(
            assessment_id="assess_isolated_02",
            name="Isolated Org Test",
            organization_name="Corp B",
            authorized_by="Lead B",
            lifecycle_status=AssessmentStatus.APPROVED,
        )
    )
    db_session.commit()

    asset_service = AssetService(session=db_session)

    # Identical target normalized string in both assessments
    asset_a, is_new_a = asset_service.register_asset(
        AssetObservation(
            assessment_id=test_assessment.assessment_id,
            raw_value="shared-name.test",
        )
    )

    asset_b, is_new_b = asset_service.register_asset(
        AssetObservation(
            assessment_id=other_assessment.assessment_id,
            raw_value="shared-name.test",
        )
    )

    assert is_new_a is True
    assert is_new_b is True
    assert asset_a.asset_id != asset_b.asset_id
    assert asset_a.assessment_id == test_assessment.assessment_id
    assert asset_b.assessment_id == other_assessment.assessment_id


def test_evidence_to_asset_linking(db_session: Session, test_assessment: Assessment):
    evidence_service = EvidenceService(session=db_session)
    asset_service = AssetService(session=db_session)

    # 1. Ingest evidence without initial asset reference
    evi, _ = evidence_service.ingest_observation(
        EvidenceObservation(
            assessment_id=test_assessment.assessment_id,
            source_name="dns_scanner",
            source_type=EvidenceSourceType.DNS_LOOKUP,
            data={"record": "A", "val": "192.168.1.10"},
        )
    )

    # 2. Register asset linked to that evidence
    asset, _ = asset_service.register_asset(
        AssetObservation(
            assessment_id=test_assessment.assessment_id,
            raw_value="192.168.1.10",
            source_evidence_id=evi.evidence_id,
        )
    )

    assert evi.evidence_id in asset.source_evidence_ids

    # 3. Verify evidence retrieval by asset
    linked_evidence = evidence_service.list_by_asset(test_assessment.assessment_id, asset.asset_id)
    assert len(linked_evidence) == 1
    assert linked_evidence[0].evidence_id == evi.evidence_id

    # 4. Explicit linking via asset_service.link_evidence
    evi2, _ = evidence_service.ingest_observation(
        EvidenceObservation(
            assessment_id=test_assessment.assessment_id,
            source_name="port_probe",
            source_type=EvidenceSourceType.SCANNER_NMAP,
            data={"port": 80, "state": "open"},
        )
    )
    updated_asset = asset_service.link_evidence(
        assessment_id=test_assessment.assessment_id,
        asset_id=asset.asset_id,
        evidence_id=evi2.evidence_id,
    )
    assert evi2.evidence_id in updated_asset.source_evidence_ids

    linked_both = evidence_service.list_by_asset(test_assessment.assessment_id, asset.asset_id)
    assert len(linked_both) == 2
