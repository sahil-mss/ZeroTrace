import React from 'react';
import { AlertTriangle } from 'lucide-react';
import type { AssessmentReportData } from '../../services/reportExport';

interface LimitationsSectionProps {
  limitations: AssessmentReportData['limitations_and_gaps'];
}

export const LimitationsSection: React.FC<LimitationsSectionProps> = ({ limitations }) => {
  return (
    <div className="report-section" data-testid="report-section-limitations">
      <h3 className="section-title text-sm row" style={{ fontWeight: 700, gap: '0.5rem', marginBottom: '0.75rem' }}>
        <AlertTriangle size={16} style={{ color: 'var(--color-sev-medium)' }} />
        <span>6. Limitations, Missing Evidence & Unverified Findings</span>
      </h3>

      <div
        className="subtle-box stack-sm"
        style={{ padding: '1rem' }}
      >
        <div className="muted text-sm">
          Integrity constraint: AI analysis and scanner heuristics must never elevate an unverified hypothesis to confirmed status without reproducible evidence artifacts.
        </div>

        <div className="row text-sm" style={{ gap: '1.5rem', fontWeight: 600 }}>
          <div>
            Unverified candidate findings:{' '}
            <span style={{ color: limitations.unverified_findings_count > 0 ? 'var(--color-sev-medium)' : 'var(--color-text-dim)' }}>
              {limitations.unverified_findings_count}
            </span>
          </div>
          <div>
            Findings lacking evidence payloads:{' '}
            <span style={{ color: limitations.findings_without_evidence_count > 0 ? 'var(--color-sev-critical)' : 'var(--color-text-dim)' }}>
              {limitations.findings_without_evidence_count}
            </span>
          </div>
        </div>

        {limitations.documented_items.length === 0 ? (
          <div className="dim text-xs" style={{ fontStyle: 'italic' }}>
            All documented findings have verified empirical evidence payloads and confirmed statuses.
          </div>
        ) : (
          <div className="stack-xs" style={{ marginTop: '0.25rem' }}>
            {limitations.documented_items.map((item, idx) => (
              <div
                key={idx}
                className="card"
                style={{
                  padding: '0.65rem 0.85rem',
                  fontSize: '0.78rem',
                }}
              >
                <div style={{ fontWeight: 600 }}>
                  [{item.finding_id}] {item.title}
                </div>
                {item.reason && (
                  <div style={{ color: 'var(--color-sev-medium)', marginTop: '0.15rem' }}>
                    {item.reason}
                  </div>
                )}
                {item.limitations.length > 0 && (
                  <ul className="muted" style={{ paddingLeft: '1.25rem', margin: '0.25rem 0 0' }}>
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
  );
};
