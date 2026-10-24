import tempfile

import pytest

from backend.storage.database import DatabaseManager
from modules.osint.normalizer import AssetNormalizer
from schemas.enums import AssetType, ScopeStatus
from schemas.models import Assessment, ScopePolicy


@pytest.fixture
def temp_db():
    db_file = tempfile.mktemp(suffix=".db")
    db = DatabaseManager(f"sqlite:///{db_file}")
    return db


def test_asset_deduplication(temp_db):
    assessment_id = "assess_norm_01"
    temp_db.save_assessment(
        Assessment(
            assessment_id=assessment_id,
            title="Norm Test",
            organization_name="TestOrg",
            authorized_by="Tester",
        )
    )
    normalizer = AssetNormalizer(temp_db)

    scope = ScopePolicy(target_domains=["lab.example.test"])

    # 1. First insertion
    asset1, is_new1 = normalizer.normalize_and_store_asset(
        assessment_id=assessment_id,
        raw_value="lab.example.test",
        source_evidence_id="evi_001",
        scope_policy=scope,
    )
    assert is_new1 is True
    assert asset1.scope_status == ScopeStatus.IN_SCOPE
    assert "evi_001" in asset1.source_evidence_ids

    # 2. Second insertion with mixed case and trailing dot
    asset2, is_new2 = normalizer.normalize_and_store_asset(
        assessment_id=assessment_id,
        raw_value="  Lab.Example.Test. ",
        source_evidence_id="evi_002",
        scope_policy=scope,
    )
    assert is_new2 is False
    assert asset2.asset_id == asset1.asset_id
    assert "evi_001" in asset2.source_evidence_ids
    assert "evi_002" in asset2.source_evidence_ids

    # Verify only 1 asset in DB
    all_assets = temp_db.list_assets(assessment_id)
    assert len(all_assets) == 1


def test_correlate_dns_records(temp_db):
    assessment_id = "assess_norm_02"
    temp_db.save_assessment(
        Assessment(
            assessment_id=assessment_id,
            title="Norm Test 2",
            organization_name="TestOrg",
            authorized_by="Tester",
        )
    )
    normalizer = AssetNormalizer(temp_db)
    scope = ScopePolicy(target_domains=["lab.example.test"], target_ips=["127.0.0.1"])

    domain_asset, _ = normalizer.normalize_and_store_asset(
        assessment_id=assessment_id,
        raw_value="lab.example.test",
        scope_policy=scope,
    )

    dns_records = {
        "A": ["127.0.0.1"],
        "CNAME": ["alias.lab.example.test"],
    }

    linked = normalizer.correlate_dns_records(
        assessment_id=assessment_id,
        domain_asset=domain_asset,
        dns_records=dns_records,
        evidence_id="evi_dns_99",
        scope_policy=scope,
    )

    assert len(linked) == 2
    ip_asset = [a for a in linked if a.asset_type == AssetType.IP_ADDRESS][0]
    assert ip_asset.value == "127.0.0.1"
    assert ip_asset.scope_status == ScopeStatus.IN_SCOPE
    assert "lab.example.test" in ip_asset.relationships["resolves_from_domain"]
