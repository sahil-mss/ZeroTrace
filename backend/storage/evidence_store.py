import hashlib
import json
import os
from pathlib import Path
from typing import Any

from schemas.enums import EvidenceSourceType
from schemas.models import Evidence, utc_now


class EvidenceStore:
    """
    Central Evidence Store for AegisPT.
    Persists immutable evidence records with cryptographic SHA-256 hashes
    and provenance tracking.
    """

    def __init__(self, storage_dir: str = "./aegis_data/evidence_blobs"):
        self.storage_path = Path(storage_dir)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_sha256(data: bytes) -> str:
        """Returns the hex SHA-256 digest of binary content."""
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    def store_raw_blob(self, raw_bytes: bytes, extension: str = "bin") -> tuple[str, str]:
        """
        Saves large tool output or raw packets to disk named by their SHA-256 hash.
        Returns: (sha256_hash, relative_filepath)
        """
        digest = self.calculate_sha256(raw_bytes)
        filename = f"{digest}.{extension}"
        filepath = self.storage_path / filename

        if not filepath.exists():
            filepath.write_bytes(raw_bytes)

        return digest, str(filepath)

    def create_evidence(
        self,
        assessment_id: str,
        source_type: EvidenceSourceType,
        tool_name: str,
        data: dict[str, Any],
        raw_payload: bytes | None = None,
        asset_id: str | None = None,
        tool_version: str = "1.0",
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Creates, hashes, and packages a verifiable Evidence object.
        """
        raw_ref = None
        if raw_payload is not None:
            digest, filepath = self.store_raw_blob(raw_payload)
            raw_ref = filepath
            final_hash = digest
        else:
            # Deterministically hash the JSON representation of data
            serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
            final_hash = self.calculate_sha256(serialized)

        evidence = Evidence(
            assessment_id=assessment_id,
            asset_id=asset_id,
            source_type=source_type,
            tool_name=tool_name,
            tool_version=tool_version,
            raw_payload_ref=raw_ref,
            data=data,
            hash_sha256=final_hash,
            collected_at=utc_now(),
            metadata=metadata or {},
        )
        return evidence

    def verify_integrity(self, evidence: Evidence) -> bool:
        """
        Validates that the stored evidence matches its recorded SHA-256 hash.
        """
        if evidence.raw_payload_ref and os.path.exists(evidence.raw_payload_ref):
            content = Path(evidence.raw_payload_ref).read_bytes()
            return self.calculate_sha256(content) == evidence.hash_sha256
        else:
            serialized = json.dumps(evidence.data, sort_keys=True, default=str).encode("utf-8")
            return self.calculate_sha256(serialized) == evidence.hash_sha256
