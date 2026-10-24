import React from 'react';
import { ListOrdered } from 'lucide-react';
import { SeverityBadge, VerificationBadge } from '../Badge';
import type { AssessmentReportData } from '../../services/reportExport';

interface RemediationChecklistSectionProps {
  checklist: AssessmentReportData['remediation_checklist'];
}

export const RemediationChecklistSection: React.FC<RemediationChecklistSectionProps> = ({ checklist }) => {
  return (
    <div className="report-section" data-testid="report-section-remediation-checklist">
      <h3 className="section-title text-sm row" style={{ fontWeight: 700, gap: '0.5rem', marginBottom: '0.75rem' }}>
        <ListOrdered size={16} style={{ color: 'var(--color-accent)' }} />
        <span>7. Prioritized Remediation Checklist ({checklist.length})</span>
      </h3>

      {checklist.length === 0 ? (
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
              {checklist.map((item) => (
                <tr key={item.finding_id}>
                  <td style={{ textAlign: 'center', fontWeight: 700 }}>#{item.priority}</td>
                  <td className="font-mono">{item.finding_id}</td>
                  <td>
                    <SeverityBadge severity={item.severity} />
                  </td>
                  <td>
                    <VerificationBadge status={item.verification_status} />
                  </td>
                  <td className="text-sm">
                    <strong>{item.title}: </strong>
                    <span className="muted">{item.action}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
