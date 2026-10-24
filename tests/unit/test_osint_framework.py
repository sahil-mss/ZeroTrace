import tempfile
from datetime import UTC, datetime, timedelta

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
from backend.app.db.repositories.audit_repo import AuditRepository
from backend.app.db.session import get_engine, get_session_factory
from backend.app.services.osint_service import OSINTCollectionService
from modules.osint.contracts import (
    CancellationToken,
    OSINTResourceBudget,
)
from modules.osint.mock_adapter import MockOSINTAdapter


@pytest.fixture
def db_session():
    """Provides an isolated SQLite database session for unit testing."""
    db_file = tempfile.mktemp(suffix=".db")
    engine = get_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def active_assessment(db_session: Session) -> Assessment:
    """Creates a valid active assessment approving lab.example.test and subdomains."""
    assessment = Assessment(
        assessment_id="assess_osint_lab_01",
        name="ZeroTrace OSINT Test",
        organization_name="Security Research Lab",
        authorized_by="Lead Security Architect",
        lifecycle_status=AssessmentStatus.APPROVED,
        permitted_profiles=[TestPermissionLevel.PASSIVE_ONLY],
        scope_rules=[
            ScopeRule(
                target_value="lab.example.test",
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
# OSINT Framework Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_mock_collection(db_session: Session, active_assessment: Assessment):
    """
    Verifies successful mock OSINT collection:
    - Ingests synthetic DNS records, subdomains, and related IPs.
    - Deterministically hashes evidence.
    - Classifies in-scope subdomains as IN_SCOPE and unapproved candidates as OUT_OF_SCOPE.
    - Emits immutable audit records.
    """
    mock_adapter = MockOSINTAdapter()
    service = OSINTCollectionService(session=db_session, adapters=[mock_adapter])

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )

    assert summary.status == "COMPLETED"
    assert summary.total_targets_queried == 1
    assert "mock_osint" in summary.adapters_executed
    assert summary.evidence_records_created > 0
    assert summary.new_assets_created > 0
    assert summary.candidate_assets_out_of_scope > 0  # external-unauthorized.test

    # Verify Assets in AssetService
    in_scope_sub = service.asset_service.get_asset_by_value(
        active_assessment.assessment_id, "api.lab.example.test"
    )
    assert in_scope_sub is not None
    assert in_scope_sub.scope_classification == ScopeStatus.IN_SCOPE
    assert len(in_scope_sub.source_evidence_ids) > 0

    # Verify Candidate Out-of-scope Asset
    candidate = service.asset_service.get_asset_by_value(
        active_assessment.assessment_id, "external-unauthorized.test"
    )
    assert candidate is not None
    assert candidate.scope_classification == ScopeStatus.OUT_OF_SCOPE

    # Verify Audit Events
    audit_repo = AuditRepository(db_session)
    events = audit_repo.list_by_assessment(active_assessment.assessment_id)
    event_types = [e.event_type for e in events]
    assert "OSINT_COLLECTION_STARTED" in event_types
    assert "OSINT_COLLECTION_COMPLETED" in event_types


@pytest.mark.asyncio
async def test_duplicate_observations_idempotency(db_session: Session, active_assessment: Assessment):
    """
    Verifies that running repeated collections on the same target does not duplicate records:
    - Evidence records are deduplicated.
    - Assets are updated rather than duplicated.
    """
    mock_adapter = MockOSINTAdapter()
    service = OSINTCollectionService(session=db_session, adapters=[mock_adapter])

    # Run 1: initial ingestion
    summary1 = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )
    initial_assets = summary1.new_assets_created
    initial_evidence = summary1.evidence_records_created
    assert initial_assets > 0
    assert initial_evidence > 0

    # Run 2: repeated ingestion
    summary2 = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )
    assert summary2.status == "COMPLETED"
    assert summary2.new_assets_created == 0
    assert summary2.duplicate_assets_updated == initial_assets
    assert summary2.evidence_records_created == 0
    assert summary2.evidence_records_deduplicated == initial_evidence

    # Confirm total assets count in DB hasn't grown
    all_assets = service.asset_service.list_assets(active_assessment.assessment_id)
    assert len(all_assets) == initial_assets


@pytest.mark.asyncio
async def test_malformed_output_handling(db_session: Session, active_assessment: Assessment):
    """
    Verifies that malformed or invalid observations from an adapter do not crash the pipeline.
    Errors are captured in summary.errors.
    """
    malformed_adapter = MockOSINTAdapter(simulate_malformed=True)
    service = OSINTCollectionService(session=db_session, adapters=[malformed_adapter])

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )

    assert len(summary.errors) > 0
    assert any("Observation processing error" in err for err in summary.errors)


@pytest.mark.asyncio
async def test_source_timeout_simulation(db_session: Session, active_assessment: Assessment):
    """
    Verifies that adapter timeout constraints are strictly enforced via asyncio.wait_for:
    - Timeout is caught.
    - Error is recorded in summary and audit logs.
    - Pipeline terminates cleanly.
    """
    timeout_adapter = MockOSINTAdapter(simulate_timeout=True)
    timeout_adapter.resource_budget = OSINTResourceBudget(timeout_seconds=0.1)

    service = OSINTCollectionService(session=db_session, adapters=[timeout_adapter])

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )

    assert len(summary.errors) > 0
    assert any("timed out after" in err for err in summary.errors)

    # Verify audit event for timeout
    audit_repo = AuditRepository(db_session)
    events = audit_repo.list_by_assessment(active_assessment.assessment_id)
    assert any(e.event_type == "OSINT_ADAPTER_TIMEOUT" for e in events)


@pytest.mark.asyncio
async def test_partial_source_failure(db_session: Session, active_assessment: Assessment):
    """
    Verifies resilience: a failing adapter does not prevent a functioning adapter
    from collecting and persisting valid intelligence.
    """
    good_adapter = MockOSINTAdapter()
    good_adapter.adapter_name = "mock_good"

    failing_adapter = MockOSINTAdapter(simulate_error=True)
    failing_adapter.adapter_name = "mock_failing"

    service = OSINTCollectionService(
        session=db_session,
        adapters=[failing_adapter, good_adapter],
    )

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )

    assert summary.status == "PARTIAL_FAILURE"
    assert "mock_failing" in summary.adapters_executed
    assert "mock_good" in summary.adapters_executed
    assert summary.new_assets_created > 0
    assert summary.evidence_records_created > 0
    assert any("mock_failing" in err for err in summary.errors)


@pytest.mark.asyncio
async def test_scope_rejection_for_unauthorized_target(db_session: Session, active_assessment: Assessment):
    """
    Verifies that targeting an unauthorized asset fails closed before any adapter is invoked.
    """
    service = OSINTCollectionService(session=db_session)

    with pytest.raises(ValueError, match="is not in approved scope"):
        await service.run_collection(
            assessment_id=active_assessment.assessment_id,
            target="unauthorized-external-corp.com",
        )

    # Verify audit event
    audit_repo = AuditRepository(db_session)
    events = audit_repo.list_by_assessment(active_assessment.assessment_id)
    assert any(e.event_type == "OSINT_TARGET_SCOPE_DENIED" for e in events)


@pytest.mark.asyncio
async def test_cooperative_cancellation(db_session: Session, active_assessment: Assessment):
    """
    Verifies cooperative cancellation token stops execution promptly.
    """
    token = CancellationToken()
    token.cancel("User aborted scan")

    service = OSINTCollectionService(session=db_session)

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
        cancellation_token=token,
    )

    assert summary.status == "CANCELLED"
    assert summary.new_assets_created == 0
    assert summary.evidence_records_created == 0


@pytest.mark.asyncio
async def test_disabled_adapter_skipped(db_session: Session, active_assessment: Assessment):
    """
    Verifies that disabled adapters are omitted from execution.
    """
    disabled_adapter = MockOSINTAdapter()
    disabled_adapter.adapter_name = "disabled_adapter"
    disabled_adapter.enabled = False

    active_adapter = MockOSINTAdapter()
    active_adapter.adapter_name = "active_adapter"

    service = OSINTCollectionService(
        session=db_session,
        adapters=[disabled_adapter, active_adapter],
    )

    summary = await service.run_collection(
        assessment_id=active_assessment.assessment_id,
        target="lab.example.test",
    )

    assert "disabled_adapter" not in summary.adapters_executed
    assert "active_adapter" in summary.adapters_executed


@pytest.mark.asyncio
async def test_unapproved_or_expired_assessment_fails_closed(db_session: Session):
    """
    Verifies that unapproved (DRAFT) or expired assessments fail closed immediately.
    """
    repo = AssessmentRepository(db_session)
    service = OSINTCollectionService(session=db_session)

    # 1. Draft assessment
    draft = repo.create(
        Assessment(
            assessment_id="assess_draft_test",
            name="Draft Test",
            organization_name="Draft Org",
            authorized_by="No One",
            lifecycle_status=AssessmentStatus.DRAFT,
        )
    )
    db_session.commit()

    with pytest.raises(ValueError, match="is not approved"):
        await service.run_collection(assessment_id=draft.assessment_id)

    # 2. Expired assessment
    expired = repo.create(
        Assessment(
            assessment_id="assess_expired_test",
            name="Expired Test",
            organization_name="Expired Org",
            authorized_by="Lead",
            lifecycle_status=AssessmentStatus.APPROVED,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
    )
    db_session.commit()

    with pytest.raises(ValueError, match="has expired"):
        await service.run_collection(assessment_id=expired.assessment_id)
