import tempfile
from collections.abc import Generator

import pytest
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    AssetType,
    AuditOutcome,
    EvidenceSourceType,
    JobStatus,
    Severity,
    TargetType,
    TestPermissionLevel,
    VerificationStatus,
)
from aegis_common.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    ResourceBudget,
    ScopeRule,
)
from alembic import command
from backend.app.db.base import Base
from backend.app.db.models import (
    AssetModel,
)
from backend.app.db.repositories import (
    AssessmentRepository,
    AssetRepository,
    AuditRepository,
    EvidenceRepository,
    FindingRepository,
    JobRepository,
)
from backend.app.db.session import get_engine, get_session_factory


@pytest.fixture
def temp_db() -> Generator[dict, None, None]:
    """Provides an isolated, clean temporary SQLite database with foreign keys enabled."""
    db_file = tempfile.mktemp(suffix=".db")
    db_url = f"sqlite:///{db_file}"
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)

    yield {
        "engine": engine,
        "session_factory": session_factory,
        "db_url": db_url,
        "db_file": db_file,
    }

    engine.dispose()


def test_sqlite_foreign_key_pragma_enabled(temp_db):
    """Verify PRAGMA foreign_keys is ON in SQLite connections."""
    engine = temp_db["engine"]
    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA foreign_keys")).scalar()
        assert result == 1, "SQLite foreign keys must be strictly enabled!"


def test_assessment_crud_and_session_restart(temp_db):
    """Verify assessment storage, retrieval, update, and survival across session restart."""
    factory = temp_db["session_factory"]

    rule = ScopeRule(
        target_type=TargetType.DOMAIN,
        target_value="test.example.internal",
        approved_ports=[80, 443],
    )
    assessment = Assessment(
        assessment_id="assess_test_01",
        name="Security Audit 2026",
        organization_name="Acme Corp",
        authorized_by="CISO Alice",
        scope_rules=[rule],
        lifecycle_status=AssessmentStatus.APPROVED,
        owner="secops",
        authorization_reference="TICKET-12345",
        authorization_acknowledged=True,
    )

    # 1. Create in Session 1
    session1: Session = factory()
    repo1 = AssessmentRepository(session1)
    saved = repo1.create(assessment)
    session1.commit()
    session1.close()

    assert saved.assessment_id == "assess_test_01"

    # 2. Retrieve in a completely new Session 2
    session2: Session = factory()
    repo2 = AssessmentRepository(session2)
    fetched = repo2.get("assess_test_01")
    assert fetched is not None
    assert fetched.assessment_id == "assess_test_01"
    assert fetched.name == "Security Audit 2026"
    assert fetched.organization_name == "Acme Corp"
    assert fetched.authorized_by == "CISO Alice"
    assert fetched.authorization_reference == "TICKET-12345"
    assert fetched.authorization_acknowledged is True
    assert len(fetched.scope_rules) == 1
    assert fetched.scope_rules[0].target_value == "test.example.internal"
    assert fetched.scope_rules[0].approved_ports == [80, 443]

    # 3. Update assessment status
    fetched.lifecycle_status = AssessmentStatus.ACTIVE
    fetched.description = "Updated assessment description"
    repo2.update(fetched)
    session2.commit()
    session2.close()

    # 4. Verify update in Session 3
    session3: Session = factory()
    repo3 = AssessmentRepository(session3)
    re_fetched = repo3.get("assess_test_01")
    assert re_fetched is not None
    assert re_fetched.lifecycle_status == AssessmentStatus.ACTIVE
    assert re_fetched.description == "Updated assessment description"
    session3.close()


def test_foreign_key_prevention_on_unrelated_assessment(temp_db):
    """Verify foreign keys prevent creating assets/jobs/evidence/findings for non-existent assessments."""
    factory = temp_db["session_factory"]

    # 1. Asset referencing non-existent assessment must fail
    with pytest.raises((IntegrityError, ValueError)):
        session = factory()
        repo = AssetRepository(session)
        orphan_asset = Asset(
            asset_id="asset_orphan",
            assessment_id="non_existent_assessment",
            asset_type=AssetType.DOMAIN,
            normalized_value="orphan.example.test",
        )
        repo.create(orphan_asset)
        session.commit()

    # 2. Direct model insertion must also trigger SQLite foreign key constraint
    session = factory()
    orphan_model = AssetModel(
        asset_id="asset_orphan_raw",
        assessment_id="non_existent_assessment",
        asset_type="DOMAIN",
        normalized_value="raw.example.test",
    )
    session.add(orphan_model)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    session.close()


def test_asset_deduplication_and_unique_constraint(temp_db):
    """Verify asset deduplication via repository upsert and unique constraint."""
    factory = temp_db["session_factory"]

    # Setup parent assessment
    session = factory()
    assess_repo = AssessmentRepository(session)
    assess_repo.create(
        Assessment(
            assessment_id="assess_asset_test",
            name="Asset Assessment",
            organization_name="Org",
            authorized_by="Lead",
        )
    )
    session.commit()

    # 1. First upsert
    asset_repo = AssetRepository(session)
    asset1 = Asset(
        asset_id="asset_01",
        assessment_id="assess_asset_test",
        asset_type=AssetType.DOMAIN,
        normalized_value="target.example.test",
        confidence=0.8,
        source_evidence_ids=["evi_1"],
        relationships={"resolves_to": ["192.168.1.1"]},
    )
    res1 = asset_repo.upsert(asset1)
    session.commit()
    assert res1.asset_id == "asset_01"

    # 2. Second upsert with identical (assessment_id, normalized_value)
    asset2 = Asset(
        asset_id="asset_02",  # Different temporary ID
        assessment_id="assess_asset_test",
        asset_type=AssetType.DOMAIN,
        normalized_value="target.example.test",
        confidence=0.95,
        source_evidence_ids=["evi_2"],
        relationships={"resolves_to": ["192.168.1.2"]},
    )
    res2 = asset_repo.upsert(asset2)
    session.commit()

    # Idempotent: Should retain initial asset_id, merged evidence and relationships
    assert res2.asset_id == "asset_01"
    assert res2.confidence == 0.95
    assert set(res2.source_evidence_ids) == {"evi_1", "evi_2"}
    assert set(res2.relationships["resolves_to"]) == {"192.168.1.1", "192.168.1.2"}

    # Database must contain exactly 1 asset
    all_assets = asset_repo.list_by_assessment("assess_asset_test")
    assert len(all_assets) == 1

    # 3. Direct insertion violating unique constraint must raise IntegrityError
    duplicate_model = AssetModel(
        asset_id="asset_dup_raw",
        assessment_id="assess_asset_test",
        asset_type="DOMAIN",
        normalized_value="target.example.test",
    )
    session.add(duplicate_model)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    session.close()


def test_evidence_integrity_and_cross_assessment_validation(temp_db):
    """Verify evidence persistence, hash lookup, and cross-assessment asset validation."""
    factory = temp_db["session_factory"]
    session = factory()

    # Create two assessments
    a_repo = AssessmentRepository(session)
    a_repo.create(
        Assessment(
            assessment_id="assess_a",
            name="Assessment Alpha",
            organization_name="OrgAlpha",
            authorized_by="Alice",
        )
    )
    a_repo.create(
        Assessment(
            assessment_id="assess_b",
            name="Assessment Beta",
            organization_name="OrgBeta",
            authorized_by="Bob",
        )
    )

    # Create asset in assessment A
    asset_repo = AssetRepository(session)
    asset_a = asset_repo.create(
        Asset(
            asset_id="asset_in_a",
            assessment_id="assess_a",
            asset_type=AssetType.URL,
            normalized_value="http://app.internal",
        )
    )
    session.commit()

    evi_repo = EvidenceRepository(session)

    # 1. Valid evidence in assessment A
    evi_valid = Evidence(
        evidence_id="evi_valid_01",
        assessment_id="assess_a",
        asset_id=asset_a.asset_id,
        source_name="NmapScanner",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        content_hash="a" * 64,
        data={"port": 80, "state": "open"},
    )
    saved_evi = evi_repo.create(evi_valid)
    session.commit()
    assert saved_evi.evidence_id == "evi_valid_01"

    # 2. Evidence in assessment B referencing asset in assessment A -> MUST BE REJECTED
    evi_invalid = Evidence(
        evidence_id="evi_cross_assess",
        assessment_id="assess_b",  # Assessment B
        asset_id=asset_a.asset_id,  # Asset belongs to Assessment A!
        source_name="NmapScanner",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        content_hash="b" * 64,
        data={"port": 443},
    )
    with pytest.raises(ValueError, match="integrity violation"):
        evi_repo.create(evi_invalid)
    session.rollback()

    # 3. Lookup by hash
    found_by_hash = evi_repo.get_by_hash("assess_a", "a" * 64)
    assert found_by_hash is not None
    assert found_by_hash.evidence_id == "evi_valid_01"
    session.close()


def test_finding_integrity_and_provenance_validation(temp_db):
    """Verify findings require valid parent assessment, valid asset, and verified evidence."""
    factory = temp_db["session_factory"]
    session = factory()

    # Setup assessment, asset, and evidence
    assess_repo = AssessmentRepository(session)
    assess_repo.create(
        Assessment(
            assessment_id="assess_f",
            name="Assessment Finding",
            organization_name="OrgFinding",
            authorized_by="Alice",
        )
    )

    asset_repo = AssetRepository(session)
    asset = asset_repo.create(
        Asset(
            asset_id="asset_f1",
            assessment_id="assess_f",
            asset_type=AssetType.URL,
            normalized_value="http://vulnerable.test",
        )
    )

    evi_repo = EvidenceRepository(session)
    evidence = evi_repo.create(
        Evidence(
            evidence_id="evi_f1",
            assessment_id="assess_f",
            asset_id=asset.asset_id,
            source_name="ZAP",
            source_type=EvidenceSourceType.SCANNER_ZAP,
            content_hash="c" * 64,
            data={"alert": "XSS"},
        )
    )
    session.commit()

    find_repo = FindingRepository(session)

    # 1. Reject finding referencing non-existent evidence
    fake_evi_finding = Finding(
        finding_id="find_fake_evi",
        assessment_id="assess_f",
        asset_id=asset.asset_id,
        title="SQL Injection",
        description="SQL injection vulnerability detected.",
        severity=Severity.HIGH,
        evidence_ids=["evi_ghost_404"],
        remediation="Use parameterized queries.",
        source_tool="ManualReview",
    )
    with pytest.raises(ValueError, match="Referenced evidence 'evi_ghost_404' does not exist"):
        find_repo.create(fake_evi_finding)
    session.rollback()

    # 2. Valid finding with real evidence
    valid_finding = Finding(
        finding_id="find_real_01",
        assessment_id="assess_f",
        asset_id=asset.asset_id,
        title="Cross-Site Scripting (Reflected)",
        description="Reflected XSS observed in query parameter 'q'.",
        cwe="CWE-79",
        severity=Severity.HIGH,
        confidence=0.9,
        verification_status=VerificationStatus.LIKELY,
        evidence_ids=[evidence.evidence_id],
        remediation="Properly encode user input in HTML context.",
        source_tool="ZAP",
    )
    saved = find_repo.create(valid_finding)
    session.commit()
    assert saved.finding_id == "find_real_01"

    # 3. Retrieve and verify fields across new session
    session.close()
    session2 = factory()
    find_repo2 = FindingRepository(session2)
    retrieved = find_repo2.get("find_real_01")
    assert retrieved is not None
    assert retrieved.title == "Cross-Site Scripting (Reflected)"
    assert retrieved.cwe == "CWE-79"
    assert retrieved.evidence_ids == [evidence.evidence_id]
    session2.close()


def test_job_persistence_and_atomic_state_transitions(temp_db):
    """Verify job lifecycle transitions, budget persistence, and audit logging."""
    factory = temp_db["session_factory"]
    session = factory()

    assess_repo = AssessmentRepository(session)
    assess_repo.create(
        Assessment(
            assessment_id="assess_job",
            name="Assessment Job",
            organization_name="OrgJob",
            authorized_by="Alice",
        )
    )
    session.commit()

    job_repo = JobRepository(session)
    job = Job(
        job_id="job_001",
        assessment_id="assess_job",
        task_type="OSINT_DNS",
        target_input="target.example.test",
        permitted_profile=TestPermissionLevel.PASSIVE_ONLY,
        resource_budget=ResourceBudget(timeout_seconds=120, max_requests_per_minute=30),
    )
    job_repo.create(job)
    session.commit()

    # Transition to RUNNING
    running_job = job_repo.update_status(
        "job_001", JobStatus.RUNNING, reason="Worker acquired lock"
    )
    session.commit()
    assert running_job.status == JobStatus.RUNNING
    assert running_job.started_at is not None
    assert len(running_job.audit_history) == 1
    assert running_job.audit_history[0].from_status == JobStatus.CREATED
    assert running_job.audit_history[0].to_status == JobStatus.RUNNING

    # Transition to COMPLETED
    completed_job = job_repo.update_status(
        "job_001", JobStatus.COMPLETED, reason="DNS enumeration complete"
    )
    session.commit()
    assert completed_job.status == JobStatus.COMPLETED
    assert completed_job.completed_at is not None
    assert len(completed_job.audit_history) == 2
    session.close()


def test_audit_event_append_only_immutability(temp_db):
    """Verify audit events are strictly append-only and cannot be overwritten."""
    factory = temp_db["session_factory"]
    session = factory()

    assess_repo = AssessmentRepository(session)
    assess_repo.create(
        Assessment(
            assessment_id="assess_audit",
            name="Assessment Audit",
            organization_name="OrgAudit",
            authorized_by="Alice",
        )
    )
    session.commit()

    audit_repo = AuditRepository(session)
    event1 = AuditEvent(
        event_id="evt_audit_01",
        assessment_id="assess_audit",
        event_type="SCOPE_CHECK_REJECTED",
        actor="operator_1",
        outcome=AuditOutcome.DENIED,
        sanitized_metadata={"reason": "Domain outside approved boundaries"},
    )
    audit_repo.record(event1)
    session.commit()

    # Attempting to re-record with the same event_id must fail!
    tampered_event = AuditEvent(
        event_id="evt_audit_01",
        assessment_id="assess_audit",
        event_type="TAMPERED_EVENT",
        actor="malicious_actor",
        outcome=AuditOutcome.SUCCESS,
        sanitized_metadata={"tampered": True},
    )
    with pytest.raises(ValueError, match="immutability violation"):
        audit_repo.record(tampered_event)
    session.rollback()

    # Verify event remains untampered in database
    retrieved = audit_repo.get("evt_audit_01")
    assert retrieved.event_type == "SCOPE_CHECK_REJECTED"
    assert retrieved.actor == "operator_1"
    session.close()


def test_alembic_clean_migration_execution(temp_db):
    """Verify that Alembic migrations run cleanly against a fresh SQLite database."""
    fresh_db_file = tempfile.mktemp(suffix=".db")
    fresh_url = f"sqlite:///{fresh_db_file}"

    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", fresh_url)

    # Run alembic upgrade to head
    command.upgrade(alembic_cfg, "head")

    # Verify tables were created
    fresh_engine = get_engine(fresh_url)
    with fresh_engine.connect() as conn:
        tables = (
            conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
            .scalars()
            .all()
        )

        expected = [
            "alembic_version",
            "assessments",
            "assets",
            "audit_events",
            "evidence",
            "findings",
            "jobs",
        ]
        for exp in expected:
            assert exp in tables, f"Expected table '{exp}' to be created by Alembic migration!"

    fresh_engine.dispose()
