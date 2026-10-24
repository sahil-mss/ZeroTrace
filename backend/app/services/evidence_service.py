"""
Evidence Service for ZeroTrace / AegisPT.

Handles immutable, cryptographically verifiable evidence provenance ingestion,
deduplication, integrity validation, and retrieval by assessment and asset.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from aegis_common.enums import DataClassification, EvidenceSourceType
from aegis_common.models import Evidence
from aegis_common.utils import sanitize_sensitive_data, utc_now
from backend.app.db.models import AssessmentModel, AssetModel
from backend.app.db.repositories.evidence_repo import EvidenceRepository
from backend.app.services.normalization import calculate_content_hash

# Common patterns for sensitive keys or credentials in raw text
SENSITIVE_TEXT_REGEX = re.compile(
    r"(?i)(password|secret|bearer\s+|token|api[_-]?key|private[_-]?key)[\s:=]+([^\s,;\"'<>]{4,})",
    re.IGNORECASE,
)


def scrub_text_excerpt(text: str | None, max_len: int = 4096) -> str | None:
    """Scrubs credential-like tokens from freeform excerpt text and bounds length."""
    if text is None:
        return None
    scrubbed = SENSITIVE_TEXT_REGEX.sub(r"\1=[REDACTED]", text)
    if len(scrubbed) > max_len:
        return scrubbed[: max_len - 3] + "..."
    return scrubbed


class RawEvidenceStorageBackend(ABC):
    """
    Documented extension point for external evidence storage backends
    (e.g., Local Filesystem, AWS S3, Google Cloud Storage, Azure Blob).
    """

    @abstractmethod
    def store_raw(self, raw_bytes: bytes, extension: str = "bin") -> tuple[str, str]:
        """
        Stores binary payload.
        Returns (sha256_hash, storage_reference_uri).
        """
        pass

    @abstractmethod
    def retrieve_raw(self, reference_uri: str) -> bytes | None:
        """Retrieves binary payload by storage reference URI."""
        pass


class LocalFilesystemEvidenceStorage(RawEvidenceStorageBackend):
    """Default local filesystem implementation of raw evidence blob storage."""

    def __init__(self, base_dir: str | Path = "./aegis_data/evidence_blobs"):
        self.base_path = Path(base_dir)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def store_raw(self, raw_bytes: bytes, extension: str = "bin") -> tuple[str, str]:
        import hashlib

        digest = hashlib.sha256(raw_bytes).hexdigest()
        clean_ext = extension.lstrip(".")
        filename = f"{digest}.{clean_ext}"
        filepath = self.base_path / filename

        if not filepath.exists():
            filepath.write_bytes(raw_bytes)

        return digest, str(filepath.resolve())

    def retrieve_raw(self, reference_uri: str) -> bytes | None:
        # Check if file path or file URL
        target_path = Path(reference_uri)
        if not target_path.exists():
            # Try parsing file:// URL
            if reference_uri.startswith("file://"):
                target_path = Path(urlparse(reference_uri).path)
        if target_path.exists() and target_path.is_file():
            return target_path.read_bytes()
        return None


@dataclass
class EvidenceObservation:
    """Structured input observation from an approved collection adapter."""

    assessment_id: str
    source_name: str
    source_type: EvidenceSourceType
    data: dict[str, Any]
    collection_method: str = "AUTOMATED_PROBE"
    asset_id: str | None = None
    raw_payload: bytes | str | None = None
    tool_version: str | None = "1.0"
    sanitized_excerpt: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    data_classification: DataClassification = DataClassification.INTERNAL
    collected_at: datetime | None = None
    # Explicit separation of AI analysis
    ai_interpretation: dict[str, Any] | None = None


class EvidenceService:
    """
    Evidence Service implementing provenance tracking, deduplication,
    integrity verification, and boundary validation for ZeroTrace.
    """

    def __init__(
        self,
        session: Session,
        raw_storage: RawEvidenceStorageBackend | None = None,
    ):
        self.session = session
        self.repo = EvidenceRepository(session)
        self.raw_storage = raw_storage or LocalFilesystemEvidenceStorage()

    def ingest_observation(self, observation: EvidenceObservation) -> tuple[Evidence, bool]:
        """
        Accepts a structured observation, validates references, hashes canonical content,
        checks for existing duplicates, and stores sanitized evidence.

        Returns: (Evidence, is_new: bool)
        """
        # 1. Validate Assessment Reference
        assessment = self.session.get(AssessmentModel, observation.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot store evidence: Assessment '{observation.assessment_id}' does not exist.")

        # 2. Validate Asset Reference and Boundary
        if observation.asset_id:
            asset = self.session.get(AssetModel, observation.asset_id)
            if not asset:
                raise ValueError(
                    f"Cannot store evidence: Referenced asset '{observation.asset_id}' does not exist."
                )
            if asset.assessment_id != observation.assessment_id:
                raise ValueError(
                    f"Cross-assessment boundary violation: Asset '{observation.asset_id}' belongs to "
                    f"assessment '{asset.assessment_id}', but observation was submitted for "
                    f"assessment '{observation.assessment_id}'."
                )

        # 3. Sanitize data and excerpt (redact credentials and sensitive tokens)
        sanitized_data = sanitize_sensitive_data(observation.data)
        sanitized_meta = sanitize_sensitive_data(observation.metadata or {})

        # Separate AI interpretations from observed factual data
        if observation.ai_interpretation:
            sanitized_meta["ai_analysis"] = sanitize_sensitive_data(observation.ai_interpretation)

        excerpt = scrub_text_excerpt(observation.sanitized_excerpt)

        # 4. Handle raw payload storage if available
        raw_ref = None
        if observation.raw_payload is not None and self.raw_storage:
            payload_bytes = (
                observation.raw_payload.encode("utf-8")
                if isinstance(observation.raw_payload, str)
                else observation.raw_payload
            )
            _, raw_ref = self.raw_storage.store_raw(payload_bytes)

        # 5. Deterministic Content Hashing
        # Hash the canonical JSON serialization of observed factual data
        content_hash = calculate_content_hash(sanitized_data)

        # 6. Deduplication Check
        # A repeated identical observation from the same source for the same target asset is idempotent
        existing = self.repo.get_by_source_and_hash(
            assessment_id=observation.assessment_id,
            source_name=observation.source_name,
            content_hash=content_hash,
            asset_id=observation.asset_id,
        )
        if existing:
            # Duplicate observation detected: idempotent return without creating a duplicate record
            return existing, False

        # 7. Create and persist new Evidence record
        evidence_domain = Evidence(
            assessment_id=observation.assessment_id,
            asset_id=observation.asset_id,
            source_name=observation.source_name,
            source_type=observation.source_type,
            collection_method=observation.collection_method,
            collected_at=observation.collected_at or utc_now(),
            content_hash=content_hash,
            raw_payload_ref=raw_ref,
            sanitized_excerpt=excerpt,
            data=sanitized_data,
            data_classification=observation.data_classification,
            tool_version=observation.tool_version or "1.0",
            metadata=sanitized_meta,
        )

        saved = self.repo.create(evidence_domain)
        self.session.flush()
        return saved, True

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        """Retrieves evidence record by unique ID."""
        return self.repo.get(evidence_id)

    def list_by_assessment(self, assessment_id: str) -> list[Evidence]:
        """Lists all evidence records associated with an assessment."""
        return self.repo.list_by_assessment(assessment_id)

    def list_by_asset(self, assessment_id: str, asset_id: str) -> list[Evidence]:
        """Lists all evidence records linked to a specific asset within an assessment."""
        return self.repo.list_by_asset(assessment_id, asset_id)

    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """
        Cryptographically verifies that stored evidence data matches its content hash.
        """
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            return False

        calculated = calculate_content_hash(evidence.data)
        return calculated == evidence.content_hash
