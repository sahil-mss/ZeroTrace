import React from 'react';
import { useApp } from '../context/AppContext';
import {
  FileText,
  Download,
  Printer,
} from 'lucide-react';
import { SeverityBadge, VerificationBadge } from '../components/Badge';

export const ReportsPage: React.FC = () => {
  const { currentAssessment, findings, assets, evidence, currentAssessmentId, addToast } =
    useApp();

  const assessmentFindings = findings.filter((f) => f.assessment_id === currentAssessmentId);
  const assessmentAssets = assets.filter((a) => a.assessment_id === currentAssessmentId);

  const criticals = assessmentFindings.filter((f) => f.severity === 'critical');
  const highs = assessmentFindings.filter((f) => f.severity === 'high');
  const mediums = assessmentFindings.filter((f) => f.severity === 'medium');

  const handleExportMarkdown = () => {
    let md = `# Security Assessment Report — AegisPT / ZeroTrace\n\n`;
    md += `**Target:** ${currentAssessment?.target}\n`;
    md += `**Assessment Name:** ${currentAssessment?.name}\n`;
    md += `**Generated At:** ${new Date().toUTCString()}\n`;
    md += `**Scope Policy:** ${currentAssessment?.scope_policy}\n\n`;

    md += `## 1. Executive Summary\n`;
    md += `This assessment evaluated the authorized lab target ${currentAssessment?.target}. A total of ${assessmentFindings.length} findings were identified, including ${criticals.length} Critical and ${highs.length} High severity issues.\n\n`;

    md += `## 2. In-Scope Asset Footprint\n`;
    assessmentAssets.forEach((ast) => {
      md += `- **${ast.hostname_or_address}** (${ast.asset_type}) via ${ast.source}\n`;
    });
    md += `\n`;

    md += `## 3. Technical Findings Breakdown\n\n`;
    assessmentFindings.forEach((f, idx) => {
      md += `### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}\n`;
      md += `- **Status:** ${f.verification_status}\n`;
      md += `- **Taxonomy:** ${f.cwe || 'N/A'} ${f.cve ? `(${f.cve})` : ''}\n`;
      md += `- **Description:** ${f.description}\n`;
      md += `- **Remediation:** ${f.remediation || 'Refer to security baseline.'}\n`;
      md += `- **Evidence:** ${f.evidence_references.join(', ') || 'None'}\n\n`;
    });

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `AegisPT_Report_${currentAssessmentId}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    addToast('Report Exported', 'Markdown report downloaded successfully.', 'success');
  };

  const handleExportJSON = () => {
    const reportData = {
      metadata: {
        platform: 'AegisPT / ZeroTrace',
        version: '1.0.0',
        generated_at: new Date().toISOString(),
      },
      assessment: currentAssessment,
      assets: assessmentAssets,
      findings: assessmentFindings,
      evidence: evidence.filter((ev) =>
        assessmentFindings.some((f) => f.evidence_references.includes(ev.id))
      ),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json;charset=utf-8;',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `AegisPT_Report_${currentAssessmentId}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    addToast('Report Exported', 'JSON data export downloaded successfully.', 'success');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header and Export Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="h1">Executive & Technical Report</h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Comprehensive assessment synthesis with evidence citations and remediation roadmaps.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-secondary" onClick={handleExportMarkdown}>
            <Download size={14} />
            <span>Export Markdown</span>
          </button>
          <button className="btn btn-secondary" onClick={handleExportJSON}>
            <FileText size={14} />
            <span>Export JSON</span>
          </button>
          <button className="btn btn-primary" onClick={handlePrint}>
            <Printer size={14} />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Report Canvas Container */}
      <div
        className="panel"
        style={{
          padding: '2.5rem',
          backgroundColor: 'var(--color-surface)',
          border: '1px solid var(--color-border)',
          display: 'flex',
          flexDirection: 'column',
          gap: '2rem',
        }}
      >
        {/* Cover / Header Section */}
        <div style={{ borderBottom: '2px solid var(--color-border)', paddingBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                color: 'var(--color-accent)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
              }}
            >
              CONFIDENTIAL SECURITY ASSESSMENT
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
              Generated: {new Date().toLocaleDateString()}
            </span>
          </div>

          <h2 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--color-text-main)' }}>
            {currentAssessment?.name || 'Security Assessment'}
          </h2>

          <div
            className="font-mono"
            style={{
              fontSize: '0.85rem',
              color: 'var(--color-text-muted)',
              marginTop: '0.35rem',
            }}
          >
            Target Scope: {currentAssessment?.target} · Status: {currentAssessment?.status.toUpperCase()}
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        <div>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.65rem' }}>
            1. Executive Summary & Risk Profile
          </h3>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-main)', lineHeight: 1.6 }}>
            An automated and analyst-assisted security assessment was conducted against the authorized lab target{' '}
            <strong>{currentAssessment?.target}</strong>. Testing strictly followed the{' '}
            <strong>{currentAssessment?.scope_policy}</strong> policy constraints. Across all discovered assets, a total of{' '}
            <strong>{assessmentFindings.length}</strong> vulnerabilities were identified. Of these,{' '}
            <strong>{criticals.length}</strong> are classified as Critical Severity, and{' '}
            <strong>{highs.length}</strong> are High Severity. Immediate remediation is required to protect database and account integrity.
          </p>
        </div>

        {/* Section 2: Severity Matrix */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '1rem',
            padding: '1.25rem',
            backgroundColor: 'var(--color-surface-subtle)',
            borderRadius: '4px',
            border: '1px solid var(--color-border)',
            textAlign: 'center',
          }}
        >
          <div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-sev-critical-text)' }}>
              {criticals.length}
            </div>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>CRITICAL</div>
          </div>
          <div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-sev-high-text)' }}>
              {highs.length}
            </div>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>HIGH</div>
          </div>
          <div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-sev-medium-text)' }}>
              {mediums.length}
            </div>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>MEDIUM</div>
          </div>
          <div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-ver-confirmed-text)' }}>
              {assessmentFindings.filter((f) => f.verification_status === 'confirmed').length}
            </div>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-text-dim)' }}>VERIFIED CONFIRMED</div>
          </div>
        </div>

        {/* Section 3: Detailed Technical Findings */}
        <div>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.85rem' }}>
            2. Verified Technical Findings
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {assessmentFindings.map((f, i) => (
              <div
                key={f.id}
                style={{
                  border: '1px solid var(--color-border)',
                  borderRadius: '4px',
                  padding: '1.25rem',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.875rem' }}>#{i + 1}</span>
                    <SeverityBadge severity={f.severity} />
                    <VerificationBadge status={f.verification_status} />
                    <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
                      {f.cwe || 'CWE Unassigned'}
                    </span>
                  </div>
                  <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
                    Asset: {f.asset_id || 'Global'}
                  </span>
                </div>

                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-main)', marginBottom: '0.4rem' }}>
                  {f.title}
                </h4>
                <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-main)', lineHeight: 1.5, marginBottom: '0.75rem' }}>
                  {f.description}
                </p>

                {f.remediation && (
                  <div
                    style={{
                      padding: '0.75rem',
                      backgroundColor: 'var(--color-surface-subtle)',
                      borderRadius: '4px',
                      fontSize: '0.8125rem',
                      lineHeight: 1.5,
                      borderLeft: '3px solid var(--color-accent)',
                    }}
                  >
                    <strong>Actionable Fix: </strong> {f.remediation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Section 4: Attestation & Provenance */}
        <div
          style={{
            borderTop: '1px solid var(--color-border)',
            paddingTop: '1.25rem',
            fontSize: '0.75rem',
            color: 'var(--color-text-dim)',
            display: 'flex',
            justifyContent: 'space-between',
          }}
        >
          <div>Policy Guard: AegisPT Deterministic Orchestrator</div>
          <div>All findings grounded in empirical evidence records.</div>
        </div>
      </div>
    </div>
  );
};
