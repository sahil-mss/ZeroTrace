import React from 'react';
import type { FindingSeverity, VerificationStatus, AssessmentStatus, ConfidenceLevel } from '../types';

export const SeverityBadge: React.FC<{ severity: FindingSeverity }> = ({ severity }) => {
  return (
    <span className={`badge badge-${severity}`} title={`Vulnerability Impact Severity: ${severity.toUpperCase()}`}>
      {severity}
    </span>
  );
};

export const ConfidenceBadge: React.FC<{ confidence: ConfidenceLevel }> = ({ confidence }) => {
  return (
    <span
      className="badge"
      style={{
        backgroundColor: 'var(--color-surface-subtle)',
        border: '1px solid var(--color-border)',
        color:
          confidence === 'high'
            ? 'var(--color-text-main)'
            : confidence === 'medium'
            ? 'var(--color-text-muted)'
            : 'var(--color-text-dim)',
        fontSize: '0.7rem',
        letterSpacing: '0.04em',
      }}
      title={`Scanner / Analyst Confidence: ${confidence.toUpperCase()}`}
    >
      <span style={{ color: 'var(--color-text-dim)', fontWeight: 500, marginRight: '2px' }}>CONF:</span>
      {confidence.toUpperCase()}
    </span>
  );
};

export const VerificationBadge: React.FC<{ status: VerificationStatus }> = ({ status }) => {
  return (
    <span
      className={`badge badge-${status}`}
      title={
        status === 'unverified'
          ? 'Unverified: Low-confidence detection. Empirical proof has NOT yet verified this finding.'
          : status === 'confirmed'
          ? 'Confirmed: Verified by captured evidence and reproducible test payload.'
          : `Verification status: ${status}`
      }
    >
      {status.replace('_', ' ')}
    </span>
  );
};

export const AssessmentStatusBadge: React.FC<{ status: AssessmentStatus }> = ({ status }) => {
  let styleClass = 'badge-unverified';
  if (status === 'in_progress') styleClass = 'badge-likely';
  if (status === 'completed') styleClass = 'badge-confirmed';
  if (status === 'failed') styleClass = 'badge-critical';
  if (status === 'cancelled') styleClass = 'badge-false_positive';

  return (
    <span className={`badge ${styleClass}`}>
      {status.replace('_', ' ')}
    </span>
  );
};
