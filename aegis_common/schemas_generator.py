import json
from pathlib import Path

from aegis_common.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    ScopeRule,
)

MODELS = {
    "assessment.json": Assessment,
    "scope_rule.json": ScopeRule,
    "asset.json": Asset,
    "evidence.json": Evidence,
    "finding.json": Finding,
    "job.json": Job,
    "audit_event.json": AuditEvent,
}


def generate_json_schemas(output_dir: str = "schemas/v1") -> dict[str, Path]:
    """
    Generates repeatable JSON Schemas from the canonical Pydantic models
    and stores them under the specified versioned directory.
    """
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    generated = {}
    for filename, model_cls in MODELS.items():
        schema_dict = model_cls.model_json_schema()
        # Add metadata banner
        schema_dict["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema_dict["title"] = f"AegisPT {model_cls.__name__} Contract v1"

        file_path = target_dir / filename
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(schema_dict, f, indent=2)
        generated[filename] = file_path

    return generated


if __name__ == "__main__":
    out = generate_json_schemas()
    print(f"Generated {len(out)} JSON Schemas under schemas/v1:")
    for name, path in out.items():
        print(f" - {name} -> {path}")
