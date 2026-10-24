import React from 'react';
import { SeverityBadge, ConfidenceBadge, VerificationBadge } from '../Badge';
import { Cpu } from 'lucide-react';
import type { AssessmentReportData } from '../../services/reportExport';

interface TechnicalFindingsSectionProps {
  findings: AssessmentReportData['finding_details'];
}

export const TechnicalFindingsSection: React.FC<TechnicalFindingsSectionProps> = ({ findings }) => {
  const hasFindings = findings.length > 0;

  return (
    <div className="report-section" data-testid="report-section-finding-details">
      <h3 className="section-title text-sm" style={{ fontWeight: 700, marginBottom: '0.85rem' }}>
        5. Technical Finding Details ({findings.length})
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
          {findings.map((f, i) => (
            <div
              key={f.id}
              className="report-card"
              data-testid={`report-finding-${f.id}`}
            >
              {/* Finding Header */}
              <div className="row-between" style={{ flexWrap: 'wrap', marginBottom: '0.75rem' }}>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  <span className="font-mono text-sm" style={{ fontWeight: 700 }}>
                    #{i + 1} {f.id}
                  </span>
                  <SeverityBadge severity={f.severity} />
                  <ConfidenceBadge confidence={f.confidence} />
                  <VerificationBadge status={f.verification_status} />
                  <span className="font-mono dim text-xs">
                    {f.taxonomy}
                  </span>
                </div>

                <div className="font-mono dim text-xs">
                  Asset: {f.affected_asset} · Origin: {f.source_tool}
                </div>
              </div>

              {/* Title & Description */}
              <h4 className="h2" style={{ fontSize: '1.05rem', marginBottom: '0.4rem' }}>
                {f.title}
              </h4>
              <p className="text-sm" style={{ lineHeight: 1.6, marginBottom: '0.75rem' }}>
                {f.description}
              </p>

              {/* Evidence References */}
              <div className="dim text-xs" style={{ marginBottom: '0.75rem' }}>
                <strong className="muted">Captured Evidence: </strong>
                {f.evidence_references.length === 0 ? (
                  <span style={{ color: 'var(--color-sev-medium)', fontStyle: 'italic' }}>
                    None (Empirical evidence absent)
                  </span>
                ) : (
                  f.evidence_references.map((id) => (
                    <span key={id} className="font-mono subtle-box text-xs" style={{ padding: '0.1rem 0.4rem', marginRight: '0.35rem' }}>
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
                  <div className="row-between" style={{ marginBottom: '0.4rem' }}>
                    <div className="row text-xs" style={{ fontWeight: 700, color: 'var(--color-accent)', textTransform: 'uppercase', gap: '0.4rem' }}>
                      <Cpu size={13} />
                      <span>AI Technical Interpretation (Advisory Inference)</span>
                    </div>
                    <span className="dim text-xs">
                      {f.ai_interpretation.is_fallback ? 'Deterministic Fallback' : `Model: ${f.ai_interpretation.provider}`}
                    </span>
                  </div>

                  <p className="text-sm" style={{ lineHeight: 1.5, margin: 0 }}>
                    {f.ai_interpretation.summary}
                  </p>

                  {f.ai_interpretation.interpretation.length > 0 && (
                    <ul className="muted text-xs" style={{ paddingLeft: '1.25rem', marginTop: '0.4rem', marginBottom: 0 }}>
                      {f.ai_interpretation.interpretation.map((pt, idx) => (
                        <li key={idx}>{pt}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Remediation Recommendations */}
              <div
                className="subtle-box"
                style={{
                  padding: '0.75rem 1rem',
                  lineHeight: 1.5,
                }}
              >
                <strong className="dim text-xs" style={{ textTransform: 'uppercase' }}>
                  Recommended Remediation:{' '}
                </strong>
                <div className="text-sm" style={{ marginTop: '0.2rem' }}>
                  {f.remediation}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
