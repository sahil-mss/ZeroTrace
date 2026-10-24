import asyncio

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.orchestrator.engine import OrchestratorEngine
from backend.storage.database import DatabaseManager
from backend.storage.evidence_store import EvidenceStore
from modules.osint.workflow import OsintWorkflow
from schemas.enums import (
    AssessmentStatus,
    AssetType,
    JobStatus,
    ScopeStatus,
    Severity,
    TestPermissionLevel,
    VerificationStatus,
)
from schemas.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    ScopePolicy,
    utc_now,
)


def create_app(db_url: str = "sqlite:///./aegis_data/aegispt.db") -> FastAPI:
    app = FastAPI(
        title="AegisPT Orchestration & Assessment API",
        version="0.1.0",
        description="Central Orchestration, Scope Enforcement, OSINT & Evidence Store for AegisPT.",
    )

    # Enable CORS for Person 3's frontend dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Instantiate storage and engines
    db = DatabaseManager(db_url)
    evidence_store = EvidenceStore()
    orchestrator = OrchestratorEngine(db, evidence_store)
    osint_workflow = OsintWorkflow(db, evidence_store)

    # Register OSINT task handlers
    orchestrator.register_task_handler("OSINT_DNS", osint_workflow.handle_dns_job)
    orchestrator.register_task_handler("OSINT_CRTSH", osint_workflow.handle_crtsh_job)
    orchestrator.register_task_handler(
        "OSINT_HTTP_PROBE", osint_workflow.handle_http_fingerprint_job
    )
    orchestrator.register_task_handler(
        "OSINT_FULL_PASSIVE", osint_workflow.handle_full_passive_recon
    )

    app.state.db = db
    app.state.evidence_store = evidence_store
    app.state.orchestrator = orchestrator
    app.state.osint_workflow = osint_workflow

    # --- Health & Info ---
    @app.get("/health", tags=["System"])
    def health_check():
        return {
            "status": "healthy",
            "service": "AegisPT Backend & Scope Engine",
            "timestamp": utc_now().isoformat(),
        }

    # --- Assessment Endpoints ---
    class CreateAssessmentRequest(BaseModel):
        title: str
        organization_name: str
        authorized_by: str
        scope: ScopePolicy
        description: str | None = ""

    @app.post(
        "/assessments",
        response_model=Assessment,
        status_code=status.HTTP_201_CREATED,
        tags=["Assessments"],
    )
    def create_assessment(req: CreateAssessmentRequest):
        # Validate that at least one target is provided
        if not (
            req.scope.target_domains
            or req.scope.target_ips
            or req.scope.target_cidrs
            or req.scope.target_urls
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assessment scope must define at least one authorized domain, IP, CIDR, or URL.",
            )

        assessment = Assessment(
            title=req.title,
            description=req.description,
            organization_name=req.organization_name,
            authorized_by=req.authorized_by,
            scope=req.scope,
            status=AssessmentStatus.APPROVED,
        )
        saved = db.save_assessment(assessment)
        db.record_audit_event(
            assessment_id=saved.assessment_id,
            event_type="ASSESSMENT_CREATED",
            actor=req.authorized_by,
            details={"title": req.title, "scope": req.scope.model_dump()},
        )
        return saved

    @app.get("/assessments", response_model=list[Assessment], tags=["Assessments"])
    def list_assessments():
        return db.list_assessments()

    @app.get("/assessments/{assessment_id}", response_model=Assessment, tags=["Assessments"])
    def get_assessment(assessment_id: str):
        assess = db.get_assessment(assessment_id)
        if not assess:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        return assess

    @app.post("/assessments/{assessment_id}/start", tags=["Assessments"])
    async def start_assessment(assessment_id: str):
        assess = db.get_assessment(assessment_id)
        if not assess:
            raise HTTPException(status_code=404, detail="Assessment not found.")

        if assess.status == AssessmentStatus.CANCELLED:
            raise HTTPException(status_code=400, detail="Cannot start a cancelled assessment.")

        assess.status = AssessmentStatus.ACTIVE
        assess.updated_at = utc_now()
        db.save_assessment(assess)

        db.record_audit_event(
            assessment_id=assessment_id,
            event_type="ASSESSMENT_STARTED",
            details={"status": "ACTIVE"},
        )

        # Enqueue initial passive OSINT discovery jobs for authorized root domains/URLs
        launched_jobs = []
        for domain in assess.scope.target_domains:
            if not domain.startswith("*."):
                job = orchestrator.enqueue_job(
                    assessment_id=assessment_id,
                    task_type="OSINT_FULL_PASSIVE",
                    target_input=domain,
                    permission_level=TestPermissionLevel.PASSIVE_ONLY,
                )
                launched_jobs.append(job.job_id)
                # Dispatch execution asynchronously in background
                asyncio.create_task(orchestrator.execute_job(job.job_id))

        for url in assess.scope.target_urls:
            job = orchestrator.enqueue_job(
                assessment_id=assessment_id,
                task_type="OSINT_HTTP_PROBE",
                target_input=url,
                permission_level=TestPermissionLevel.PASSIVE_ONLY,
            )
            launched_jobs.append(job.job_id)
            asyncio.create_task(orchestrator.execute_job(job.job_id))

        return {
            "message": "Assessment activated and initial reconnaissance jobs dispatched.",
            "assessment_id": assessment_id,
            "status": assess.status.value,
            "enqueued_jobs": launched_jobs,
        }

    @app.post("/assessments/{assessment_id}/cancel", tags=["Assessments"])
    def cancel_assessment(assessment_id: str, reason: str = "User invoked immediate cancel"):
        assess = db.get_assessment(assessment_id)
        if not assess:
            raise HTTPException(status_code=404, detail="Assessment not found.")

        cancelled = orchestrator.cancel_assessment(assessment_id, reason=reason)
        return {
            "message": "Assessment and all active jobs successfully cancelled.",
            "assessment_id": assessment_id,
            "status": (
                cancelled.status.value
                if hasattr(cancelled.status, "value")
                else str(cancelled.status)
            ).upper(),
        }

    # --- Assets ---
    @app.get("/assessments/{assessment_id}/assets", response_model=list[Asset], tags=["Assets"])
    def list_assets(
        assessment_id: str,
        scope_status: ScopeStatus | None = None,
        asset_type: AssetType | None = None,
    ):
        assets = db.list_assets(assessment_id)
        if scope_status:
            assets = [a for a in assets if a.scope_status == scope_status]
        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]
        return assets

    # --- Evidence ---
    @app.get(
        "/assessments/{assessment_id}/evidence", response_model=list[Evidence], tags=["Evidence"]
    )
    def list_evidence(assessment_id: str):
        return db.list_evidence(assessment_id)

    @app.post(
        "/assessments/{assessment_id}/evidence",
        response_model=Evidence,
        status_code=201,
        tags=["Evidence"],
    )
    def submit_evidence(assessment_id: str, evidence: Evidence):
        """Allows Person 2's scanners or Person 3's AI to register verified evidence."""
        if evidence.assessment_id != assessment_id:
            raise HTTPException(
                status_code=400, detail="Mismatched assessment_id in evidence record."
            )

        # Cryptographically verify the evidence before storing
        if not evidence_store.verify_integrity(evidence):
            raise HTTPException(
                status_code=400,
                detail="Evidence hash verification failed! Data does not match hash_sha256.",
            )

        saved = db.save_evidence(evidence)
        return saved

    # --- Findings ---
    @app.get(
        "/assessments/{assessment_id}/findings", response_model=list[Finding], tags=["Findings"]
    )
    def list_findings(
        assessment_id: str,
        severity: Severity | None = None,
        verification_status: VerificationStatus | None = None,
    ):
        findings = db.list_findings(assessment_id)
        if severity:
            findings = [f for f in findings if f.severity == severity]
        if verification_status:
            findings = [f for f in findings if f.verification_status == verification_status]
        return findings

    @app.post(
        "/assessments/{assessment_id}/findings",
        response_model=Finding,
        status_code=201,
        tags=["Findings"],
    )
    def submit_finding(assessment_id: str, finding: Finding):
        """
        Allows Person 2's scanners or Person 3's models to submit normalized findings.
        Enforces evidence ID validation and target scope checks!
        """
        if finding.assessment_id != assessment_id:
            raise HTTPException(status_code=400, detail="Mismatched assessment_id in finding.")

        assess = db.get_assessment(assessment_id)
        if not assess:
            raise HTTPException(status_code=404, detail="Assessment not found.")

        # Rule: Do not let finding be created without supporting evidence in the store
        existing_evidence = {e.evidence_id for e in db.list_evidence(assessment_id)}
        for eid in finding.evidence_ids:
            if eid not in existing_evidence:
                raise HTTPException(
                    status_code=400,
                    detail=f"Evidence ID '{eid}' does not exist in assessment evidence store.",
                )

        # Rule: Cannot mark CONFIRMED without verification status explicitly backed
        if finding.verification_status == VerificationStatus.CONFIRMED and finding.confidence < 0.7:
            raise HTTPException(
                status_code=400,
                detail="A finding cannot be marked CONFIRMED with low confidence (< 0.70).",
            )

        saved = db.save_finding(finding)
        db.record_audit_event(
            assessment_id=assessment_id,
            event_type="FINDING_RECORDED",
            actor=finding.tool_name,
            details={
                "finding_id": saved.finding_id,
                "title": saved.title,
                "severity": saved.severity.value,
                "verification_status": saved.verification_status.value,
            },
        )
        return saved

    # --- Jobs & Orchestration ---
    class EnqueueJobRequest(BaseModel):
        task_type: str
        target_input: str
        permission_level: TestPermissionLevel = TestPermissionLevel.PASSIVE_ONLY
        timeout_seconds: int = 180

    @app.post(
        "/assessments/{assessment_id}/jobs", response_model=Job, status_code=201, tags=["Jobs"]
    )
    def enqueue_job(assessment_id: str, req: EnqueueJobRequest):
        try:
            job = orchestrator.enqueue_job(
                assessment_id=assessment_id,
                task_type=req.task_type,
                target_input=req.target_input,
                permission_level=req.permission_level,
                timeout_seconds=req.timeout_seconds,
            )
            if job.status == JobStatus.QUEUED:
                asyncio.create_task(orchestrator.execute_job(job.job_id))
            return job
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/assessments/{assessment_id}/jobs", response_model=list[Job], tags=["Jobs"])
    def list_jobs(assessment_id: str):
        return db.list_jobs(assessment_id)

    @app.get("/jobs/{job_id}", response_model=Job, tags=["Jobs"])
    def get_job(job_id: str):
        job = db.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")
        return job

    @app.post("/jobs/{job_id}/cancel", response_model=Job, tags=["Jobs"])
    def cancel_job(job_id: str):
        try:
            return orchestrator.cancel_job(job_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    # --- Audit Trail & Activity ---
    @app.get("/assessments/{assessment_id}/events", response_model=list[AuditEvent], tags=["Audit"])
    def list_audit_events(assessment_id: str):
        return db.list_audit_events(assessment_id)

    # --- Report / Export ---
    @app.get("/assessments/{assessment_id}/report", tags=["Reports"])
    def get_assessment_report(assessment_id: str):
        assess = db.get_assessment(assessment_id)
        if not assess:
            raise HTTPException(status_code=404, detail="Assessment not found.")

        assets = db.list_assets(assessment_id)
        findings = db.list_findings(assessment_id)
        evidence = db.list_evidence(assessment_id)
        events = db.list_audit_events(assessment_id)

        return {
            "assessment": assess.model_dump(mode="json"),
            "summary": {
                "total_assets": len(assets),
                "in_scope_assets": len(
                    [a for a in assets if a.scope_status == ScopeStatus.IN_SCOPE]
                ),
                "total_findings": len(findings),
                "critical_findings": len([f for f in findings if f.severity == Severity.CRITICAL]),
                "high_findings": len([f for f in findings if f.severity == Severity.HIGH]),
                "medium_findings": len([f for f in findings if f.severity == Severity.MEDIUM]),
                "low_findings": len([f for f in findings if f.severity == Severity.LOW]),
                "info_findings": len([f for f in findings if f.severity == Severity.INFO]),
                "confirmed_findings": len(
                    [f for f in findings if f.verification_status == VerificationStatus.CONFIRMED]
                ),
                "total_evidence_records": len(evidence),
                "total_audit_events": len(events),
            },
            "assets": [a.model_dump(mode="json") for a in assets],
            "findings": [f.model_dump(mode="json") for f in findings],
            "evidence": [e.model_dump(mode="json") for e in evidence],
            "audit_trail": [ev.model_dump(mode="json") for ev in events],
            "exported_at": utc_now().isoformat(),
        }

    return app


app = create_app()
