import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_common.enums import ScopeStatus
from aegis_common.models import Asset
from backend.app.db.models import AssessmentModel, AssetModel


class AssetRepository:
    """Repository handling persistence, deduplication, and retrieval of target assets."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, asset: Asset) -> Asset:
        # Verify assessment exists
        assessment = self.session.get(AssessmentModel, asset.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot create asset: Assessment {asset.assessment_id} does not exist.")

        model = AssetModel.from_domain(asset)
        self.session.add(model)
        self.session.flush()
        return model.to_domain()

    def upsert(self, asset: Asset) -> Asset:
        """
        Idempotently inserts an asset or updates existing observation data if
        (assessment_id, normalized_value) is already present.
        """
        # Verify assessment exists
        assessment = self.session.get(AssessmentModel, asset.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot upsert asset: Assessment {asset.assessment_id} does not exist.")

        existing = self.get_by_value(asset.assessment_id, asset.normalized_value)
        if existing:
            # Update observation timestamps, confidence and metadata
            model = self.session.get(AssetModel, existing.asset_id)
            if model:
                model.last_seen = asset.last_seen
                model.confidence = max(model.confidence, asset.confidence)
                # Never change an out-of-scope asset into an approved/in-scope one simply because another source reports it
                if model.scope_classification == ScopeStatus.OUT_OF_SCOPE.value and asset.scope_classification.value == ScopeStatus.IN_SCOPE.value:
                    pass  # Keep OUT_OF_SCOPE
                else:
                    model.scope_classification = asset.scope_classification.value

                # Merge metadata
                if asset.metadata:
                    existing_meta = json.loads(model.metadata_json) if model.metadata_json else {}
                    existing_meta.update(asset.metadata)
                    model.metadata_json = json.dumps(existing_meta)

                # Merge relationships
                existing_rels = json.loads(model.relationships_json) if model.relationships_json else {}
                for k, v in asset.relationships.items():
                    existing_rels.setdefault(k, [])
                    for item in v:
                        if item not in existing_rels[k]:
                            existing_rels[k].append(item)
                model.relationships_json = json.dumps(existing_rels)

                # Merge source evidence IDs
                existing_evidence = json.loads(model.source_evidence_ids_json) if model.source_evidence_ids_json else []
                for eid in asset.source_evidence_ids:
                    if eid not in existing_evidence:
                        existing_evidence.append(eid)
                model.source_evidence_ids_json = json.dumps(existing_evidence)

                self.session.flush()
                return model.to_domain()

        return self.create(asset)

    def update(self, asset: Asset) -> Asset:
        model = self.session.get(AssetModel, asset.asset_id)
        if not model:
            raise ValueError(f"Asset {asset.asset_id} not found.")

        model.last_seen = asset.last_seen
        model.confidence = asset.confidence
        model.scope_classification = asset.scope_classification.value
        model.source_evidence_ids_json = json.dumps(asset.source_evidence_ids)
        model.relationships_json = json.dumps(asset.relationships)
        model.metadata_json = json.dumps(asset.metadata)
        self.session.flush()
        return model.to_domain()

    def get(self, asset_id: str) -> Asset | None:
        model = self.session.get(AssetModel, asset_id)
        if not model:
            return None
        return model.to_domain()

    def get_by_value(self, assessment_id: str, value: str) -> Asset | None:
        stmt = select(AssetModel).where(
            AssetModel.assessment_id == assessment_id,
            AssetModel.normalized_value == value,
        )
        model = self.session.scalars(stmt).first()
        if not model:
            return None
        return model.to_domain()

    def list_by_assessment(
        self,
        assessment_id: str,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Asset]:
        stmt = (
            select(AssetModel)
            .where(AssetModel.assessment_id == assessment_id)
            .order_by(AssetModel.first_seen.asc())
        )
        if offset is not None:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        models = self.session.scalars(stmt).all()
        return [m.to_domain() for m in models]

