import React, { useMemo } from 'react';
import { useApp } from '../context/useApp';
import {
  Download,
  Printer,
  FileSpreadsheet,
} from 'lucide-react';
import {
  compileAssessmentReport,
  exportReportMarkdown,
  exportReportJSON,
} from '../services/reportExport';
import { ExecutiveSummarySection } from '../components/report/ExecutiveSummarySection';
import { ScopeAndMethodologySection } from '../components/report/ScopeAndMethodologySection';
import { AssetInventorySection } from '../components/report/AssetInventorySection';
import { FindingsSummarySection } from '../components/report/FindingsSummarySection';
import { TechnicalFindingsSection } from '../components/report/TechnicalFindingsSection';
import { LimitationsSection } from '../components/report/LimitationsSection';
import { RemediationChecklistSection } from '../components/report/RemediationChecklistSection';

export const ReportsPage: React.FC = () => {
  const {
    currentAssessment,
    assets,
    findings,
    evidence,
    aiAnalysis,
    addToast,
  } = useApp();


  const report = useMemo(() => {
    if (!currentAssessment) return null;
    return compileAssessmentReport(
      currentAssessment,
      assets,
      findings,
      evidence,
      aiAnalysis
    );
  }, [currentAssessment, assets, findings, evidence, aiAnalysis]);

  if (!currentAssessment || !report) {
    return (
      <div className="panel" style={{ padding: '3rem', textAlign: 'center' }}>
        <h2 className="section-title">No Active Assessment Selected</h2>
        <p className="muted text-sm" style={{ marginTop: '0.5rem' }}>
          Select or launch an authorized assessment to view and export the empirical security dossier.
        </p>
      </div>
    );
  }

  const {
    assessment,
    executive_summary,
    scope_and_methodology,
    asset_inventory,
    findings_summary,
    finding_details,
    limitations_and_gaps,
    remediation_checklist,
  } = report;

  const handleExportMarkdown = () => {
    exportReportMarkdown(report, `ZeroTrace_Report_${assessment.id}_${new Date().toISOString().split('T')[0]}.md`);
    addToast('Report Exported', 'Executive Markdown report downloaded', 'success');
  };

  const handleExportJSON = () => {
    exportReportJSON(report, `ZeroTrace_Report_${assessment.id}_${new Date().toISOString().split('T')[0]}.json`);
    addToast('Report Exported', 'Structured JSON audit data downloaded', 'success');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="stack">
      {/* Top Bar with Export Controls (Hidden during browser print) */}
      <div className="row-between responsive-stack no-print" style={{ paddingBottom: '0.75rem', borderBottom: '1px solid var(--color-border)' }}>
        <div>
          <h1 className="h1">Executive & Technical Report</h1>
          <p className="muted text-sm" style={{ marginTop: '0.2rem' }}>
            Official assessment dossier compiled exclusively from verified findings, assets, and empirical evidence.
          </p>
        </div>

        <div className="row">
          <button
            className="btn btn-secondary"
            onClick={handleExportMarkdown}
            data-testid="export-markdown-btn"
            title="Download executive Markdown dossier"
          >
            <Download size={14} />
            <span>Export Markdown</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleExportJSON}
            data-testid="export-json-btn"
            title="Download structured JSON report data"
          >
            <FileSpreadsheet size={14} />
            <span>Export JSON</span>
          </button>
          <button
            className="btn btn-primary"
            onClick={handlePrint}
            data-testid="print-report-btn"
            title="Trigger browser print-to-PDF layout"
          >
            <Printer size={14} />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Main Printable Report Canvas */}
      <div className="report-canvas panel" data-testid="report-canvas">
        {/* SECTION 1: Assessment Title, Identifier, Target Scope & Timestamps */}
        <div className="report-section report-header-banner">
          <div className="row-between" style={{ marginBottom: '0.65rem' }}>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                color: 'var(--color-accent)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
              }}
            >
              CONFIDENTIAL SECURITY AUDIT REPORT · AEGISPT
            </span>
            <span className="font-mono text-sm dim">
              REPORT GENERATED: {new Date(report.metadata.generated_at).toLocaleString()}
            </span>
          </div>

          <h2 className="h1" style={{ fontSize: '1.75rem' }}>
            {assessment.name}
          </h2>

          <div className="report-meta-row">
            <div>
              <strong className="dim">IDENTIFIER: </strong>
              <span className="font-mono">{assessment.id}</span>
            </div>
            <div>
              <strong className="dim">TARGET SCOPE: </strong>
              <span className="font-mono">{assessment.target}</span>
            </div>
            <div>
              <strong className="dim">POLICY: </strong>
              <span className="font-mono">{assessment.scope_policy}</span>
            </div>
            <div>
              <strong className="dim">STATUS: </strong>
              <span style={{ fontWeight: 600 }}>
                {assessment.status.toUpperCase()}
              </span>
            </div>
            <div>
              <strong className="dim">CREATED: </strong>
              <span>{new Date(assessment.created_at).toLocaleString()}</span>
            </div>
            {assessment.completed_at && (
              <div>
                <strong className="dim">COMPLETED: </strong>
                <span>{new Date(assessment.completed_at).toLocaleString()}</span>
              </div>
            )}
          </div>
        </div>

        {/* SECTION 2: Executive Summary */}
        <ExecutiveSummarySection summary={executive_summary} />

        {/* SECTION 3: Assessment Scope & Methodology */}
        <ScopeAndMethodologySection data={scope_and_methodology} />

        {/* SECTION 4: Asset Inventory Summary */}
        <AssetInventorySection inventory={asset_inventory} />

        {/* SECTION 5: Findings Distribution by Severity */}
        <FindingsSummarySection summary={findings_summary} />

        {/* SECTION 6: Technical Finding Details */}
        <TechnicalFindingsSection findings={finding_details} />

        {/* SECTION 7: Limitations, Missing Evidence & Gaps */}
        <LimitationsSection limitations={limitations_and_gaps} />

        {/* SECTION 8: Prioritized Remediation Checklist */}
        <RemediationChecklistSection checklist={remediation_checklist} />

        {/* Attestation & Signature Footer */}
        <div
          className="row-between text-xs dim"
          style={{
            borderTop: '1px solid var(--color-border)',
            paddingTop: '1.5rem',
            flexWrap: 'wrap',
          }}
        >
          <div>
            <strong>Orchestrator:</strong> ZeroTrace / AegisPT Policy Engine (Controlled Execution)
          </div>
          <div style={{ fontStyle: 'italic' }}>
            All statistics and claims derived strictly from stored assessment data.
          </div>
        </div>
      </div>
    </div>
  );
};
