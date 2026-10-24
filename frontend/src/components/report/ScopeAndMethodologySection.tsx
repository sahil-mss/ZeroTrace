import React from 'react';
import { ShieldCheck } from 'lucide-react';
import type { AssessmentReportData } from '../../services/reportExport';

interface ScopeAndMethodologySectionProps {
  data: AssessmentReportData['scope_and_methodology'];
}

export const ScopeAndMethodologySection: React.FC<ScopeAndMethodologySectionProps> = ({ data }) => {
  return (
    <div className="report-section" data-testid="report-section-methodology">
      <h3 className="section-title text-sm row" style={{ fontWeight: 700, gap: '0.5rem', marginBottom: '0.75rem' }}>
        <ShieldCheck size={16} style={{ color: 'var(--color-accent)' }} />
        <span>2. Scope & Methodology</span>
      </h3>
      <p className="muted text-sm" style={{ marginBottom: '0.85rem' }}>
        Testing activities were strictly restricted to the authorized target parameters. All scanner adapters operated under bounded safety constraints without autonomous or destructive exploit execution.
      </p>

      <div className="grid-4 responsive-grid">
        <div className="subtle-box">
          <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Scope Rule</div>
          <div className="font-mono text-sm" style={{ fontWeight: 600, marginTop: '0.2rem' }}>{data.policy}</div>
        </div>
        <div className="subtle-box">
          <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Permitted Profiles</div>
          <div className="text-sm" style={{ marginTop: '0.2rem' }}>
            {data.allowed_checks.join(', ') || 'Passive inspection only'}
          </div>
        </div>
        <div className="subtle-box">
          <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Discovered Services</div>
          <div className="metric-value" style={{ fontSize: '1.25rem', marginTop: '0.1rem' }}>
            {data.observed_services_count}
          </div>
        </div>
        <div className="subtle-box">
          <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Recorded Evidence Artifacts</div>
          <div className="metric-value" style={{ fontSize: '1.25rem', marginTop: '0.1rem' }}>
            {data.recorded_evidence_count}
          </div>
        </div>
      </div>
    </div>
  );
};
