"""Repeatable End-to-End Demonstration for AegisPT Security Testing Engine.

TASK 3: Demonstrates the full Stage 1-10 pipeline:
1. Verify local lab reachability.
2. Create an authorized assessment.
3. Validate engagement scope.
4. Run the Nmap adapter (or parse verified Nmap XML fixture if binary absent).
5. Parse Nmap output into service observations.
6. Run the OWASP ZAP passive scanning workflow (or parse verified ZAP JSON fixture if daemon offline).
7. Parse ZAP alerts.
8. Normalize scanner results using NormalizationPipeline.
9. Verify findings using VerificationEngine (plugins + ground truth).
10. Store raw evidence with SHA-256 hashes.
11. Generate evaluation benchmark metrics (Precision, Recall, F1 score).
12. Produce a final structured ScanJobResponse report for Person 1 and Person 3.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

from aegispt.security_engine.core.scope import LocalScopeValidator
from aegispt.security_engine.evaluation.harness import BenchmarkHarness
from aegispt.security_engine.evaluation.lab_manager import LabManager
from aegispt.security_engine.evaluation.scenarios import JUICE_SHOP_BENCHMARK_SCENARIOS
from aegispt.security_engine.integrations.nmap.parser import NmapXMLParser
from aegispt.security_engine.integrations.nmap.scanner import NmapScanner
from aegispt.security_engine.integrations.zap.parser import ZAPAlertParser
from aegispt.security_engine.integrations.zap.scanner import ZAPScanner
from aegispt.security_engine.normalization.pipeline import NormalizationPipeline
from aegispt.security_engine.schemas.enums import (
    AssetType,
    JobStatus,
    PermissionLevel,
    ScanStatus,
    VerificationStatus,
)
from aegispt.security_engine.schemas.job import ScanJobRequest, ScanJobResponse
from aegispt.security_engine.schemas.profile import (
    MOCK_BASELINE_PROFILE,
    NMAP_FAST_DISCOVERY_PROFILE,
    ZAP_PASSIVE_BASELINE_PROFILE,
    ResourceBudget,
)
from aegispt.security_engine.schemas.result import RawScanEvidence, ScanRequest, ScanResult
from aegispt.security_engine.schemas.target import ScanTarget
from aegispt.security_engine.service import ScannerService
from aegispt.security_engine.verification.engine import VerificationEngine


def run_end_to_end_demonstration(verbose: bool = True) -> dict[str, Any]:
    """Execute the complete 12-step demonstration flow."""
    demo_log: list[str] = []

    def log(msg: str) -> None:
        demo_log.append(msg)
        if verbose:
            print(msg)

    log("=" * 75)
    log("  AEGISPT SECURITY TESTING ENGINE — END-TO-END DEMONSTRATION")
    log("=" * 75)

    # -------------------------------------------------------------------------
    # STEP 1: Check Local Vulnerable Application Readiness
    # -------------------------------------------------------------------------
    log("\n[STEP 1] Checking Local Vulnerable Application Readiness...")
    lab_mgr = LabManager.from_file("lab/lab_config.json")
    readiness = lab_mgr.get_readiness_report()
    log(f"  Target Lab URL: {readiness.target_url}")
    log(f"  Reachability: {readiness.is_reachable}")
    log(f"  Readiness Status: {readiness.message}")

    # -------------------------------------------------------------------------
    # STEP 2: Create Authorized Assessment
    # -------------------------------------------------------------------------
    log("\n[STEP 2] Initializing Authorized Assessment...")
    assessment_id = f"assess-demo-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    asset_id = "asset-juice-shop-01"
    target = ScanTarget(
        asset_type=AssetType.WEB_URL,
        target_value="http://127.0.0.1:3000",
        ports=[3000],
        is_in_scope=True,
        metadata={"lab": "owasp_juice_shop", "environment": "local_dev"},
    )
    log(f"  Assessment ID: {assessment_id}")
    log(f"  Asset ID: {asset_id}")
    log(f"  Target Endpoint: {target.target_value} (Ports: {target.ports})")

    # -------------------------------------------------------------------------
    # STEP 3: Validate Scope
    # -------------------------------------------------------------------------
    log("\n[STEP 3] Validating Target Scope (LocalScopeValidator)...")
    scope_validator = LocalScopeValidator()
    scope_validator.validate_target(target, assessment_id=assessment_id)
    log("  [PASS] Scope validation confirmed: target is within authorized local boundaries.")

    # -------------------------------------------------------------------------
    # STEP 4 & 5: Run Nmap Adapter & Parse Output
    # -------------------------------------------------------------------------
    log("\n[STEP 4 & 5] Executing Nmap Port & Service Discovery...")
    nmap_scanner = NmapScanner()
    if shutil.which("nmap"):
        log("  Found system Nmap executable; dispatching live scan...")
        nmap_req = ScanRequest(
            scanner_id="nmap",
            target=ScanTarget(asset_type=AssetType.IP_ADDRESS, target_value="127.0.0.1", ports=[3000]),
            profile=NMAP_FAST_DISCOVERY_PROFILE,
        )
        nmap_res = nmap_scanner.run_scan(nmap_req)
        observations = nmap_res.observations
    else:
        log("  Nmap binary not detected in PATH; loading verified Nmap XML fixture...")
        fixture_path = Path("tests/fixtures/nmap/sample_open_ports.xml")
        observations = NmapXMLParser.parse_file(fixture_path, strict=True)

    log(f"  Parsed {len(observations)} factual service observation(s):")
    for obs in observations:
        log(f"    - Port {obs.port}/{obs.protocol} ({obs.state}): service={obs.service_name} product={obs.product} {obs.service_version}")

    # -------------------------------------------------------------------------
    # STEP 6 & 7: Run ZAP Passive Scan & Parse Alerts
    # -------------------------------------------------------------------------
    log("\n[STEP 6 & 7] Executing OWASP ZAP Passive Scan Workflow...")
    zap_scanner = ZAPScanner()
    zap_fixture = Path("tests/fixtures/zap/sample_alerts_flat.json")
    simulated_alerts = zap_fixture.read_text(encoding="utf-8") if zap_fixture.is_file() else "{}"

    zap_request = ScanRequest(
        scanner_id="owasp_zap",
        target=target,
        profile=ZAP_PASSIVE_BASELINE_PROFILE,
        options={"simulated_alerts_json": simulated_alerts},
    )
    zap_result = zap_scanner.run_scan(zap_request)
    raw_findings = zap_result.findings
    log(f"  ZAP Status: {zap_result.status.value}")
    log(f"  Extracted {len(raw_findings)} raw vulnerability alert(s).")

    # -------------------------------------------------------------------------
    # STEP 8: Normalize Results
    # -------------------------------------------------------------------------
    log("\n[STEP 8] Normalizing Findings with Deduplication and Schema Alignment...")
    normalized_findings = NormalizationPipeline.normalize_scan_result(
        result=zap_result,
        assessment_id=assessment_id,
    )
    for nf in normalized_findings:
        nf.asset_id = asset_id
    log(f"  Normalized & Deduplicated Finding Count: {len(normalized_findings)}")
    for f in normalized_findings:
        log(f"    - [{f.severity.value}] {f.title} (CWE-{f.cwe}) -> ID: {f.finding_id}")

    # -------------------------------------------------------------------------
    # STEP 9: Verify a Supported Lab Finding
    # -------------------------------------------------------------------------
    log("\n[STEP 9] Deterministic Finding Verification (VerificationEngine)...")
    v_engine = VerificationEngine()
    verified_findings, audit_records = v_engine.verify_all(
        findings=normalized_findings,
        assessment_scope={target.target_value, asset_id},
    )

    log(f"  Verification Records Produced: {len(audit_records)}")
    for record in audit_records:
        log(f"    - Finding {record.finding_id}: {record.previous_status} -> {record.new_status.value} (Method: {record.verification_method}, Reason: {record.reason})")

    # -------------------------------------------------------------------------
    # STEP 10: Store Evidence
    # -------------------------------------------------------------------------
    log("\n[STEP 10] Preserving Raw Cryptographic Evidence Artifacts...")
    artifacts_dir = Path("artifacts/scans")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = artifacts_dir / f"demo_evidence_{assessment_id}.json"
    evidence_content = json.dumps([f.model_dump(mode="json") for f in verified_findings], indent=2)
    evidence_bytes = evidence_content.encode("utf-8")
    evidence_path.write_bytes(evidence_bytes)
    evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()

    evidence_artifact = RawScanEvidence(
        scanner_id="aegispt_security_engine",
        file_path=str(evidence_path),
        sha256_hash=evidence_sha256,
        byte_size=len(evidence_bytes),
        content_type="application/json",
        raw_snippet=evidence_content[:200],
    )
    log(f"  Evidence File: {evidence_artifact.file_path}")
    log(f"  SHA-256: {evidence_artifact.sha256_hash}")
    log(f"  Size: {evidence_artifact.byte_size} bytes")

    # -------------------------------------------------------------------------
    # STEP 11: Generate Evaluation Summary
    # -------------------------------------------------------------------------
    log("\n[STEP 11] Running Benchmark Evaluation Harness...")
    eval_report = BenchmarkHarness.evaluate(
        scanner_id=zap_scanner.SCANNER_ID,
        scan_profile=ZAP_PASSIVE_BASELINE_PROFILE.profile_id,
        findings=verified_findings,
        scenarios=JUICE_SHOP_BENCHMARK_SCENARIOS,
        tool_version=zap_scanner.VERSION,
        total_runtime_seconds=zap_result.duration_seconds,
    )
    metrics = eval_report.metrics
    log(f"  Total Scenarios Evaluated: {eval_report.total_scenarios}")
    log(f"  Confusion Matrix: TP={metrics.true_positives}, FP={metrics.false_positives}, TN={metrics.true_negatives}, FN={metrics.false_negatives}")
    log(f"  Precision: {metrics.precision:.2%}")
    log(f"  Recall:    {metrics.recall:.2%}")
    log(f"  F1 Score:  {metrics.f1_score:.4f}")
    log(f"  Scan Completion Rate: {metrics.scan_completion_rate:.2%}")

    # -------------------------------------------------------------------------
    # STEP 12: Produce Report Through Shared Backend Interface
    # -------------------------------------------------------------------------
    log("\n[STEP 12] Emitting Final ScanJobResponse Report for Person 1 / Person 3...")
    job_response = ScanJobResponse(
        job_id=f"job-{assessment_id}",
        status=JobStatus.COMPLETED,
        scanner_metadata=zap_scanner.get_metadata(),
        duration_seconds=zap_result.duration_seconds,
        findings=verified_findings,
        evidence_references=[evidence_artifact.artifact_id, str(evidence_path)],
        verification_summary={f.finding_id: VerificationStatus(f.verification_status) for f in verified_findings},
        logs=demo_log,
    )
    log(f"  Job ID: {job_response.job_id}")
    log(f"  Status: {job_response.status.value}")
    log(f"  Verified Findings Summary: {job_response.verification_summary}")
    log("=" * 75)
    log("  DEMONSTRATION SUCCESSFULLY CONCLUDED")
    log("=" * 75)

    return {
        "assessment_id": assessment_id,
        "readiness": readiness.model_dump(),
        "observations_count": len(observations),
        "findings_count": len(verified_findings),
        "evidence_sha256": evidence_artifact.sha256_hash,
        "metrics": metrics.model_dump(),
        "job_response": job_response.model_dump(mode="json"),
    }
