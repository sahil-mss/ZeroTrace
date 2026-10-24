import React from 'react';
import { useApp } from '../context/useApp';
import {
  FileText,
  Download,
  Printer,
  ShieldCheck,
  AlertTriangle,
  Server,
  Layers,
  Cpu,
  ListOrdered,
  FileSpreadsheet,
} from 'lucide-react';
import { SeverityBadge, VerificationBadge, ConfidenceBadge } from '../components/Badge';
import {
  compileAssessmentReport,
  exportReportJSON,
  exportReportMarkdown,
} from '../services/reportExport';

export const ReportsPage: React.FC = () => {
  const {
    currentAssessment,
    findings,
    assets,
    evidence,
    aiAnalysis,
    addToast,
  } = useApp();

  const report = compileAssessmentReport(
    currentAssessment,
    assets,
    findings,
    evidence,
    aiAnalysis
  );

  const handleExportMarkdown = () => {
    if (!report) return;
    exportReportMarkdown(report);
    addToast('Report Exported', 'Markdown report generated and downloaded.', 'success');
  };

  const handleExportJSON = () => {
    if (!report) return;
    exportReportJSON(report);
    addToast('Report Exported', 'Structured JSON dataset downloaded.', 'success');
  };

  const handlePrint = () => {
    window.print();
  };

  if (!currentAssessment || !report) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center' }}>
        <AlertTriangle size={36} style={{ color: 'var(--color-sev-medium)', margin: '0 auto 1rem' }} />
        <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--color-text-main)' }}>
          No Assessment Selected
        </h2>
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', marginTop: '0.5rem' }}>
          Please select an assessment from the Assessments tab or top selector to view and generate reports.
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

  const hasFindings = finding_details.length > 0;
  const hasAssets = asset_inventory.total > 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Bar with Export Controls (Hidden during browser print) */}
      <div
        className="no-print"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          paddingBottom: '0.75rem',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <div>
          <h1 className="h1">Executive & Technical Report</h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Official assessment dossier compiled exclusively from verified findings, assets, and empirical evidence.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
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
      <div
        className="report-canvas panel"
        style={{
          padding: '2.5rem',
          backgroundColor: 'var(--color-surface)',
          border: '1px solid var(--color-border)',
          display: 'flex',
          flexDirection: 'column',
          gap: '2.25rem',
        }}
        data-testid="report-canvas"
      >
        {/* SECTION 1: Assessment Title, Identifier, Target Scope & Timestamps */}
        <div
          className="report-section"
          style={{
            borderBottom: '2px solid var(--color-border)',
            paddingBottom: '1.5rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
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
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
              REPORT GENERATED: {new Date(report.metadata.generated_at).toLocaleString()}
            </span>
          </div>

          <h2 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text-main)', lineHeight: 1.25 }}>
            {assessment.name}
          </h2>

          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '1.25rem',
              marginTop: '0.85rem',
              fontSize: '0.8125rem',
              color: 'var(--color-text-muted)',
            }}
          >
            <div>
              <strong style={{ color: 'var(--color-text-dim)' }}>IDENTIFIER: </strong>
              <span className="font-mono">{assessment.id}</span>
            </div>
            <div>
              <strong style={{ color: 'var(--color-text-dim)' }}>TARGET SCOPE: </strong>
              <span className="font-mono">{assessment.target}</span>
            </div>
            <div>
              <strong style={{ color: 'var(--color-text-dim)' }}>POLICY: </strong>
              <span className="font-mono">{assessment.scope_policy}</span>
            </div>
            <div>
              <strong style={{ color: 'var(--color-text-dim)' }}>STATUS: </strong>
              <span style={{ fontWeight: 600, color: 'var(--color-text-main)' }}>
                {assessment.status.toUpperCase()}
              </span>
            </div>
            <div>
              <strong style={{ color: 'var(--color-text-dim)' }}>CREATED: </strong>
              <span>{new Date(assessment.created_at).toLocaleString()}</span>
            </div>
            {assessment.completed_at && (
              <div>
                <strong style={{ color: 'var(--color-text-dim)' }}>COMPLETED: </strong>
                <span>{new Date(assessment.completed_at).toLocaleString()}</span>
              </div>
            )}
          </div>
        </div>

        {/* SECTION 2: Executive Summary */}
        <div className="report-section" data-testid="report-section-executive-summary">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FileText size={16} style={{ color: 'var(--color-accent)' }} />
            <span>1. Executive Summary</span>
          </h3>
          <p
            style={{
              fontSize: '0.875rem',
              color: 'var(--color-text-main)',
              lineHeight: 1.65,
              backgroundColor: 'var(--color-surface-subtle)',
              padding: '1rem 1.25rem',
              borderRadius: '4px',
              borderLeft: '4px solid var(--color-accent)',
            }}
          >
            {executive_summary}
          </p>
        </div>

        {/* SECTION 3: Assessment Scope & Methodology */}
        <div className="report-section" data-testid="report-section-methodology">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={16} style={{ color: 'var(--color-accent)' }} />
            <span>2. Scope & Methodology</span>
          </h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginBottom: '0.85rem' }}>
            Testing activities were strictly restricted to the authorized target parameters. All scanner adapters operated under bounded safety constraints without autonomous or destructive exploit execution.
          </p>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1rem',
            }}
          >
            <div style={{ padding: '0.85rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>Scope Rule</div>
              <div className="font-mono" style={{ fontSize: '0.8125rem', fontWeight: 600, marginTop: '0.2rem' }}>{scope_and_methodology.policy}</div>
            </div>
            <div style={{ padding: '0.85rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>Permitted Profiles</div>
              <div style={{ fontSize: '0.78rem', marginTop: '0.2rem' }}>
                {scope_and_methodology.allowed_checks.join(', ') || 'Passive inspection only'}
              </div>
            </div>
            <div style={{ padding: '0.85rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>Discovered Services</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-text-main)', marginTop: '0.1rem' }}>
                {scope_and_methodology.observed_services_count}
              </div>
            </div>
            <div style={{ padding: '0.85rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>Recorded Evidence Artifacts</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-text-main)', marginTop: '0.1rem' }}>
                {scope_and_methodology.recorded_evidence_count}
              </div>
            </div>
          </div>
        </div>

        {/* SECTION 4: Asset Inventory Summary */}
        <div className="report-section" data-testid="report-section-assets">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={16} style={{ color: 'var(--color-accent)' }} />
            <span>3. Asset Inventory Summary ({asset_inventory.total})</span>
          </h3>

          {!hasAssets ? (
            <div style={{ padding: '1.5rem', textAlign: 'center', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px dashed var(--color-border)', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
              Zero assets discovered or assigned to this assessment record.
            </div>
          ) : (
            <div className="table-container table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset ID</th>
                    <th>Hostname / Address</th>
                    <th>Type</th>
                    <th>Discovery Source</th>
                    <th>Services Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {asset_inventory.items.map((ast) => (
                    <tr key={ast.id}>
                      <td className="font-mono" style={{ fontWeight: 600 }}>{ast.id}</td>
                      <td className="font-mono" style={{ color: 'var(--color-accent)' }}>{ast.hostname_or_address}</td>
                      <td>
                        <span style={{ textTransform: 'uppercase', fontSize: '0.72rem', fontWeight: 600, padding: '0.1rem 0.4rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '3px', border: '1px solid var(--color-border)' }}>
                          {ast.asset_type}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8125rem' }}>{ast.source}</td>
                      <td style={{ fontSize: '0.8125rem' }}>
                        {ast.services.length === 0 ? (
                          <span style={{ color: 'var(--color-text-dim)' }}>None</span>
                        ) : (
                          ast.services.map((s, idx) => (
                            <div key={idx} className="font-mono" style={{ fontSize: '0.75rem' }}>
                              {s.port}/{s.protocol} {s.banner ? `(${s.banner})` : ''}
                            </div>
                          ))
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* SECTION 5: Findings Summary Grouped by Severity */}
        <div className="report-section" data-testid="report-section-findings-summary">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={16} style={{ color: 'var(--color-accent)' }} />
            <span>4. Findings Distribution by Severity & Status</span>
          </h3>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.75rem',
              marginBottom: '1rem',
            }}
          >
            <div style={{ padding: '1rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-sev-critical-text)' }}>
                {findings_summary.by_severity.critical}
              </div>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>CRITICAL</div>
            </div>
            <div style={{ padding: '1rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-sev-high-text)' }}>
                {findings_summary.by_severity.high}
              </div>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>HIGH</div>
            </div>
            <div style={{ padding: '1rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-sev-medium-text)' }}>
                {findings_summary.by_severity.medium}
              </div>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>MEDIUM</div>
            </div>
            <div style={{ padding: '1rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-sev-low-text)' }}>
                {findings_summary.by_severity.low}
              </div>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>LOW</div>
            </div>
            <div style={{ padding: '1rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text-muted)' }}>
                {findings_summary.by_severity.informational}
              </div>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>INFO</div>
            </div>
            <div style={{ padding: '1rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-ver-confirmed-text)' }}>
                {findings_summary.by_verification.confirmed}
              </div>
              <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>CONFIRMED</div>
            </div>
          </div>
        </div>

        {/* SECTION 6: Individual Finding Details */}
        <div className="report-section" data-testid="report-section-finding-details">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.85rem' }}>
            5. Technical Finding Details ({finding_details.length})
          </h3>

          {!hasFindings ? (
            <div
              style={{
                padding: '2rem',
                textAlign: 'center',
                backgroundColor: 'var(--color-surface-subtle)',
                borderRadius: '4px',
                border: '1px dashed var(--color-border)',
                color: 'var(--color-text-muted)',
                fontSize: '0.875rem',
              }}
              data-testid="empty-findings-state"
            >
              No vulnerability findings recorded for this assessment.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {finding_details.map((f, i) => (
                <div
                  key={f.id}
                  className="report-card"
                  style={{
                    border: '1px solid var(--color-border)',
                    borderRadius: '4px',
                    padding: '1.25rem',
                    backgroundColor: 'var(--color-surface)',
                  }}
                  data-testid={`report-finding-${f.id}`}
                >
                  {/* Finding Header */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <span className="font-mono" style={{ fontWeight: 700, fontSize: '0.875rem' }}>
                        #{i + 1} {f.id}
                      </span>
                      <SeverityBadge severity={f.severity as any} />
                      <ConfidenceBadge confidence={f.confidence as any} />
                      <VerificationBadge status={f.verification_status as any} />
                      <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-dim)' }}>
                        {f.taxonomy}
                      </span>
                    </div>

                    <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
                      Asset: {f.affected_asset} · Origin: {f.source_tool}
                    </div>
                  </div>

                  {/* Title & Description */}
                  <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-main)', marginBottom: '0.4rem' }}>
                    {f.title}
                  </h4>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-main)', lineHeight: 1.6, marginBottom: '0.75rem' }}>
                    {f.description}
                  </p>

                  {/* Evidence References */}
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)', marginBottom: '0.75rem' }}>
                    <strong style={{ color: 'var(--color-text-muted)' }}>Captured Evidence: </strong>
                    {f.evidence_references.length === 0 ? (
                      <span style={{ color: 'var(--color-sev-medium)', fontStyle: 'italic' }}>
                        None (Empirical evidence absent)
                      </span>
                    ) : (
                      f.evidence_references.map((id) => (
                        <span key={id} className="font-mono" style={{ backgroundColor: 'var(--color-surface-subtle)', padding: '0.1rem 0.4rem', borderRadius: '3px', border: '1px solid var(--color-border)', marginRight: '0.35rem' }}>
                          {id}
                        </span>
                      ))
                    )}
                  </div>

                  {/* AI Interpretation (Visibly Separated & Clearly Labeled) */}
                  {f.ai_interpretation && (
                    <div
                      style={{
                        padding: '0.85rem 1rem',
                        backgroundColor: 'var(--color-surface-subtle)',
                        borderRadius: '4px',
                        borderLeft: '3px solid var(--color-accent)',
                        marginBottom: '0.75rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-accent)', textTransform: 'uppercase' }}>
                          <Cpu size={13} />
                          <span>AI Technical Interpretation (Advisory Inference)</span>
                        </div>
                        <span style={{ fontSize: '0.68rem', color: 'var(--color-text-dim)' }}>
                          {f.ai_interpretation.is_fallback ? 'Deterministic Fallback' : `Model: ${f.ai_interpretation.provider}`}
                        </span>
                      </div>

                      <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-main)', lineHeight: 1.5, margin: 0 }}>
                        {f.ai_interpretation.summary}
                      </p>

                      {f.ai_interpretation.interpretation.length > 0 && (
                        <ul style={{ paddingLeft: '1.25rem', fontSize: '0.78rem', color: 'var(--color-text-muted)', marginTop: '0.4rem', marginBottom: 0 }}>
                          {f.ai_interpretation.interpretation.map((pt, idx) => (
                            <li key={idx}>{pt}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  {/* Remediation Recommendations */}
                  <div
                    style={{
                      padding: '0.75rem 1rem',
                      backgroundColor: 'var(--color-surface-subtle)',
                      borderRadius: '4px',
                      border: '1px solid var(--color-border)',
                      fontSize: '0.8125rem',
                      lineHeight: 1.5,
                    }}
                  >
                    <strong style={{ color: 'var(--color-text-dim)', textTransform: 'uppercase', fontSize: '0.7rem' }}>
                      Recommended Remediation:{' '}
                    </strong>
                    <div style={{ marginTop: '0.2rem', color: 'var(--color-text-main)' }}>
                      {f.remediation}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* SECTION 7: Limitations, Missing Evidence, and Unverified Findings */}
        <div className="report-section" data-testid="report-section-limitations">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} style={{ color: 'var(--color-sev-medium)' }} />
            <span>6. Limitations, Missing Evidence & Unverified Findings</span>
          </h3>

          <div
            style={{
              padding: '1rem',
              backgroundColor: 'var(--color-surface-subtle)',
              borderRadius: '4px',
              border: '1px solid var(--color-border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem',
            }}
          >
            <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
              Integrity constraint: AI analysis and scanner heuristics must never elevate an unverified hypothesis to confirmed status without reproducible evidence artifacts.
            </div>

            <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.8125rem', fontWeight: 600 }}>
              <div>
                Unverified candidate findings:{' '}
                <span style={{ color: limitations_and_gaps.unverified_findings_count > 0 ? 'var(--color-sev-medium)' : 'var(--color-text-dim)' }}>
                  {limitations_and_gaps.unverified_findings_count}
                </span>
              </div>
              <div>
                Findings lacking evidence payloads:{' '}
                <span style={{ color: limitations_and_gaps.findings_without_evidence_count > 0 ? 'var(--color-sev-critical)' : 'var(--color-text-dim)' }}>
                  {limitations_and_gaps.findings_without_evidence_count}
                </span>
              </div>
            </div>

            {limitations_and_gaps.documented_items.length === 0 ? (
              <div style={{ fontSize: '0.78rem', color: 'var(--color-text-dim)', fontStyle: 'italic' }}>
                All documented findings have verified empirical evidence payloads and confirmed statuses.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.25rem' }}>
                {limitations_and_gaps.documented_items.map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: '0.65rem 0.85rem',
                      backgroundColor: 'var(--color-surface)',
                      borderRadius: '3px',
                      border: '1px solid var(--color-border)',
                      fontSize: '0.78rem',
                    }}
                  >
                    <div style={{ fontWeight: 600, color: 'var(--color-text-main)' }}>
                      [{item.finding_id}] {item.title}
                    </div>
                    {item.reason && (
                      <div style={{ color: 'var(--color-sev-medium)', marginTop: '0.15rem' }}>
                        {item.reason}
                      </div>
                    )}
                    {item.limitations.length > 0 && (
                      <ul style={{ paddingLeft: '1.25rem', margin: '0.25rem 0 0', color: 'var(--color-text-muted)' }}>
                        {item.limitations.map((lim, i) => (
                          <li key={i}>{lim}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* SECTION 8: Prioritized Remediation Checklist */}
        <div className="report-section" data-testid="report-section-remediation-checklist">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ListOrdered size={16} style={{ color: 'var(--color-accent)' }} />
            <span>7. Prioritized Remediation Checklist ({remediation_checklist.length})</span>
          </h3>

          {remediation_checklist.length === 0 ? (
            <div style={{ padding: '1.5rem', textAlign: 'center', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px dashed var(--color-border)', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
              No prioritized remediation actions required for this assessment.
            </div>
          ) : (
            <div className="table-container table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '80px', textAlign: 'center' }}>Priority</th>
                    <th style={{ width: '110px' }}>Finding ID</th>
                    <th style={{ width: '100px' }}>Severity</th>
                    <th style={{ width: '120px' }}>Verification</th>
                    <th>Actionable Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {remediation_checklist.map((item) => (
                    <tr key={item.finding_id}>
                      <td style={{ textAlign: 'center', fontWeight: 700 }}>#{item.priority}</td>
                      <td className="font-mono">{item.finding_id}</td>
                      <td>
                        <SeverityBadge severity={item.severity as any} />
                      </td>
                      <td>
                        <VerificationBadge status={item.verification_status as any} />
                      </td>
                      <td style={{ fontSize: '0.8125rem' }}>
                        <strong>{item.title}: </strong>
                        <span style={{ color: 'var(--color-text-muted)' }}>{item.action}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Attestation & Signature Footer */}
        <div
          style={{
            borderTop: '1px solid var(--color-border)',
            paddingTop: '1.5rem',
            fontSize: '0.75rem',
            color: 'var(--color-text-dim)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.5rem',
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
