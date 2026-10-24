import React from 'react';
import type { Finding } from '../../types';

interface RemediationSectionProps {
  finding: Finding;
}

export const RemediationSection: React.FC<RemediationSectionProps> = ({ finding }) => {
  return (
    <div
      style={{
        border: '1px solid var(--color-border)',
        borderRadius: '4px',
        padding: '1.25rem',
        backgroundColor: 'var(--color-surface)',
      }}
    >
      <h3 className="section-title text-sm" style={{ textTransform: 'uppercase', marginBottom: '0.65rem' }}>
        Deterministic Remediation & Hardening Guidance
      </h3>
      <div
        className="muted text-sm"
        style={{
          lineHeight: 1.6,
          backgroundColor: 'var(--color-surface-subtle)',
          padding: '0.85rem 1rem',
          borderRadius: '4px',
          border: '1px solid var(--color-border-subtle)',
        }}
      >
        <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', margin: 0 }}>
          {finding.remediation || 'Apply standard patch and hardening guidelines for this component.'}
        </pre>
      </div>
    </div>
  );
};
