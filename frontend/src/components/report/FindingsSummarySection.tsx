import React from 'react';
import { Layers } from 'lucide-react';
import type { AssessmentReportData } from '../../services/reportExport';

interface FindingsSummarySectionProps {
  summary: AssessmentReportData['findings_summary'];
}

export const FindingsSummarySection: React.FC<FindingsSummarySectionProps> = ({ summary }) => {
  return (
    <div className="report-section" data-testid="report-section-findings-summary">
      <h3 className="section-title text-sm row" style={{ fontWeight: 700, gap: '0.5rem', marginBottom: '0.75rem' }}>
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
        <div className="subtle-box" style={{ textAlign: 'center', padding: '1rem' }}>
          <div className="metric-value" style={{ color: 'var(--color-sev-critical-text)', marginTop: 0 }}>
            {summary.by_severity.critical}
          </div>
          <div className="dim text-xs" style={{ fontWeight: 600 }}>CRITICAL</div>
        </div>
        <div className="subtle-box" style={{ textAlign: 'center', padding: '1rem' }}>
          <div className="metric-value" style={{ color: 'var(--color-sev-high-text)', marginTop: 0 }}>
            {summary.by_severity.high}
          </div>
          <div className="dim text-xs" style={{ fontWeight: 600 }}>HIGH</div>
        </div>
        <div className="subtle-box" style={{ textAlign: 'center', padding: '1rem' }}>
          <div className="metric-value" style={{ color: 'var(--color-sev-medium-text)', marginTop: 0 }}>
            {summary.by_severity.medium}
          </div>
          <div className="dim text-xs" style={{ fontWeight: 600 }}>MEDIUM</div>
        </div>
        <div className="subtle-box" style={{ textAlign: 'center', padding: '1rem' }}>
          <div className="metric-value" style={{ color: 'var(--color-sev-low-text)', marginTop: 0 }}>
            {summary.by_severity.low}
          </div>
          <div className="dim text-xs" style={{ fontWeight: 600 }}>LOW</div>
        </div>
        <div className="subtle-box" style={{ textAlign: 'center', padding: '1rem' }}>
          <div className="metric-value muted" style={{ marginTop: 0 }}>
            {summary.by_severity.informational}
          </div>
          <div className="dim text-xs" style={{ fontWeight: 600 }}>INFO</div>
        </div>
        <div className="subtle-box" style={{ textAlign: 'center', padding: '1rem' }}>
          <div className="metric-value" style={{ color: 'var(--color-ver-confirmed-text)', marginTop: 0 }}>
            {summary.by_verification.confirmed}
          </div>
          <div className="dim text-xs" style={{ fontWeight: 600 }}>CONFIRMED</div>
        </div>
      </div>
    </div>
  );
};
