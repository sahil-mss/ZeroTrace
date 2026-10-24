import React from 'react';

interface ExecutiveSummarySectionProps {
  summary: string;
}

export const ExecutiveSummarySection: React.FC<ExecutiveSummarySectionProps> = ({ summary }) => {
  return (
    <div className="report-section" data-testid="report-section-executive-summary">
      <h3 className="section-title text-sm" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.5rem' }}>
        1. Executive Risk Summary
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
        {summary}
      </p>
    </div>
  );
};
