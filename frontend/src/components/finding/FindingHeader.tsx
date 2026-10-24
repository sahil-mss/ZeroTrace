import React from 'react';
import type { Finding } from '../../types';
import { SeverityBadge, VerificationBadge, ConfidenceBadge } from '../Badge';
import { AlertTriangle, Info, CheckCircle2 } from 'lucide-react';

interface FindingHeaderProps {
  finding: Finding;
}

export const FindingHeader: React.FC<FindingHeaderProps> = ({ finding }) => {
  const isUnverified = finding.verification_status === 'unverified';
  const isFalsePositive = finding.verification_status === 'false_positive';
  const isConfirmed = finding.verification_status === 'confirmed';

  return (
    <div
      style={{
        padding: '1.25rem 1.5rem',
        borderBottom: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.65rem',
      }}
    >
      {/* Badge Cluster with Explicit Severity & Confidence Separation */}
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <span className="font-mono text-xs dim" style={{ fontWeight: 600 }}>
          {finding.id}
        </span>
        <SeverityBadge severity={finding.severity} />
        <ConfidenceBadge confidence={finding.confidence} />
        <VerificationBadge status={finding.verification_status} />
        <span
          className="subtle-box text-xs muted"
          style={{ padding: '0.15rem 0.45rem' }}
        >
          Origin: {finding.source_tool}
        </span>
      </div>

      <h2 id="finding-detail-title" className="h1" style={{ fontSize: '1.25rem', lineHeight: 1.3 }}>
        {finding.title}
      </h2>

      {/* Verification Status Banner */}
      {isUnverified && (
        <div
          style={{
            padding: '0.75rem 1rem',
            backgroundColor: 'var(--color-sev-medium-bg)',
            border: '1px solid var(--color-sev-medium-border)',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.6rem',
            fontSize: '0.78rem',
            color: 'var(--color-sev-medium-text)',
            lineHeight: 1.5,
          }}
        >
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>STATUS: UNVERIFIED</strong> — Empirical verification has not occurred for this candidate finding.
            Scanner alerts represent heuristic suspicions. <em>Under system safety rules, AI analysis cannot and does not confirm a vulnerability without captured proof.</em>
          </div>
        </div>
      )}

      {isFalsePositive && (
        <div
          style={{
            padding: '0.75rem 1rem',
            backgroundColor: 'var(--color-ver-fp-bg)',
            border: '1px solid var(--color-ver-fp-border)',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            fontSize: '0.78rem',
            color: 'var(--color-ver-fp-text)',
          }}
        >
          <Info size={16} style={{ flexShrink: 0 }} />
          <div>
            <strong>STATUS: FALSE POSITIVE</strong> — Verified as non-exploitable or safe server behavior through empirical probe.
          </div>
        </div>
      )}

      {isConfirmed && (
        <div
          style={{
            padding: '0.75rem 1rem',
            backgroundColor: 'var(--color-ver-confirmed-bg)',
            border: '1px solid var(--color-ver-confirmed-border)',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            fontSize: '0.78rem',
            color: 'var(--color-ver-confirmed-text)',
          }}
        >
          <CheckCircle2 size={16} style={{ flexShrink: 0 }} />
          <div>
            <strong>STATUS: CONFIRMED</strong> — Empirically reproduced and backed by verifiable evidence records.
          </div>
        </div>
      )}
    </div>
  );
};
