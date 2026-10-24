import React from 'react';
import type { Finding, Evidence } from '../../types';
import { FileCode, Copy, Check, AlertTriangle } from 'lucide-react';

interface EvidencePanelProps {
  finding: Finding;
  evidence: Evidence[];
  copiedEvidenceId: string | null;
  onCopyRaw: (evId: string, text?: string) => void;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({
  finding,
  evidence,
  copiedEvidenceId,
  onCopyRaw,
}) => {
  const findingEvidence = evidence.filter((ev) =>
    finding.evidence_references.includes(ev.id)
  );

  return (
    <div
      style={{
        border: '1px solid var(--color-border)',
        borderRadius: '4px',
        overflow: 'hidden',
      }}
    >
      <div
        className="row-between panel-header"
        style={{
          padding: '0.75rem 1rem',
          backgroundColor: 'var(--color-surface-subtle)',
          flexWrap: 'wrap',
        }}
      >
        <div className="row">
          <FileCode size={15} style={{ color: 'var(--color-accent)' }} />
          <span style={{ fontSize: '0.8125rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Empirical Evidence Records ({findingEvidence.length})
          </span>
        </div>
        <span className="font-mono text-xs dim">
          Strict Provenance Tracking
        </span>
      </div>

      <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        {findingEvidence.length === 0 ? (
          <div
            style={{
              padding: '1.5rem',
              textAlign: 'center',
              backgroundColor: 'var(--color-surface-subtle)',
              borderRadius: '4px',
              border: '1px dashed var(--color-border)',
            }}
          >
            <AlertTriangle size={24} style={{ color: 'var(--color-sev-medium-text)', marginBottom: '0.5rem' }} />
            <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-main)' }}>
              Zero Verified Evidence Records
            </div>
            <p className="muted text-sm" style={{ maxWidth: '420px', margin: '0.25rem auto 0 auto', lineHeight: 1.5 }}>
              This finding lacks empirical evidence files or raw HTTP captures. Under zero-trust evaluation rules, lack of proof prevents vulnerability verification.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {findingEvidence.map((ev) => (
              <div
                key={ev.id}
                style={{
                  border: '1px solid var(--color-border)',
                  borderRadius: '4px',
                  backgroundColor: 'var(--color-surface)',
                  overflow: 'hidden',
                }}
              >
                <div
                  className="row-between"
                  style={{
                    padding: '0.55rem 0.85rem',
                    backgroundColor: 'var(--color-surface-subtle)',
                    borderBottom: '1px solid var(--color-border-subtle)',
                    fontSize: '0.75rem',
                    flexWrap: 'wrap',
                  }}
                >
                  <div className="row font-mono text-xs" style={{ gap: '0.4rem' }}>
                    <span style={{ fontWeight: 700, color: 'var(--color-accent)' }}>
                      {ev.id}
                    </span>
                    <span className="dim">·</span>
                    <span className="muted">Collector: {ev.source}</span>
                    <span className="dim">·</span>
                    <span className="dim">{new Date(ev.observed_at).toLocaleTimeString()}</span>
                  </div>

                  {ev.raw_data && (
                    <button
                      onClick={() => onCopyRaw(ev.id, ev.raw_data)}
                      className="btn btn-secondary btn-xs"
                      title="Copy payload to clipboard"
                    >
                      {copiedEvidenceId === ev.id ? (
                        <>
                          <Check size={12} /> Copied
                        </>
                      ) : (
                        <>
                          <Copy size={12} /> Copy Payload
                        </>
                      )}
                    </button>
                  )}
                </div>

                <div style={{ padding: '0.875rem', fontSize: '0.8125rem' }}>
                  <p style={{ color: 'var(--color-text-main)', marginBottom: '0.5rem', fontWeight: 500 }}>
                    {ev.description}
                  </p>

                  {ev.reference_or_artifact_location && (
                    <div
                      className="font-mono text-xs dim"
                      style={{ marginBottom: '0.5rem' }}
                    >
                      Artifact Path: {ev.reference_or_artifact_location}
                    </div>
                  )}

                  {ev.raw_data && (
                    <pre
                      className="font-mono text-xs"
                      style={{
                        backgroundColor: 'var(--color-surface-subtle)',
                        padding: '0.75rem',
                        borderRadius: '4px',
                        border: '1px solid var(--color-border-subtle)',
                        overflowX: 'auto',
                        maxHeight: '180px',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {ev.raw_data}
                    </pre>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
