import os
import shutil
import tempfile

import pytest

from backend.storage.evidence_store import EvidenceStore
from schemas.enums import EvidenceSourceType


@pytest.fixture
def temp_evidence_store():
    temp_dir = tempfile.mkdtemp()
    store = EvidenceStore(storage_dir=temp_dir)
    yield store
    shutil.rmtree(temp_dir)


def test_evidence_hashing_and_integrity(temp_evidence_store):
    data = {"tool": "nmap", "port": 80, "state": "open"}
    evidence = temp_evidence_store.create_evidence(
        assessment_id="assess_test_01",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        tool_name="nmap",
        data=data,
    )

    assert evidence.hash_sha256 is not None
    assert len(evidence.hash_sha256) == 64
    assert temp_evidence_store.verify_integrity(evidence) is True

    # Tamper with data -> integrity must fail
    evidence.data["port"] = 8080
    assert temp_evidence_store.verify_integrity(evidence) is False


def test_raw_blob_storage(temp_evidence_store):
    raw_xml = b"<nmaprun><host><address addr='127.0.0.1'/></host></nmaprun>"
    evidence = temp_evidence_store.create_evidence(
        assessment_id="assess_test_02",
        source_type=EvidenceSourceType.SCANNER_NMAP,
        tool_name="nmap",
        data={"summary": "1 host up"},
        raw_payload=raw_xml,
    )

    assert evidence.raw_payload_ref is not None
    assert os.path.exists(evidence.raw_payload_ref)
    assert temp_evidence_store.verify_integrity(evidence) is True
