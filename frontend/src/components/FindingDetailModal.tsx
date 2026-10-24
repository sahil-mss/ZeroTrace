import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import {
  X,
  FileCode,
  BrainCircuit,
  Copy,
  Check,
  ArrowLeft,
  AlertTriangle,
  Info,
  CheckCircle2,
} from 'lucide-react';
import { SeverityBadge, VerificationBadge, ConfidenceBadge } from './Badge';

export const FindingDetailModal: React.FC = () => {
  const { selectedFindingId, setSelectedFindingId, findings, evidence, aiAnalysis, addToast } =
    useApp();
  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);

  if (!selectedFindingId) return null;

  const finding = findings.find((f) => f.id === selectedFindingId);
  if (!finding) return null;

  const findingEvidence = evidence.filter((ev) => finding.evidence_references.includes(ev.id));
  const analysis = aiAnalysis[finding.id];
  const isUnverified = finding.verification_status === 'unverified';
  const isFalsePositive = finding.verification_status === 'false_positive';
  const isConfirmed = finding.verification_status === 'confirmed';
  const hasEvidence = findingEvidence.length > 0;

  const handleCopyRaw = (evId: string, text?: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedEvidenceId(evId);
    addToast('Payload Copied', `Evidence snippet ${evId} copied to clipboard`, 'info');
    setTimeout(() => setCopiedEvidenceId(null), 2000);
  };

  const handleClose = () => {
    // Simply close detail panel without modifying filter state
    setSelectedFindingId(null);
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        backdropFilter: 'blur(2px)',
        zIndex: 9000,
        display: 'flex',
        justifyContent: 'flex-end',
      }}
      onClick={handleClose}
      role="dialog"
      aria-modal="true"
      aria-label={`Finding details: ${finding.title}`}
    >
      <div
        style={{
          width: '840px',
          maxWidth: '100%',
          height: '100%',
          backgroundColor: 'var(--color-surface)',
          borderLeft: '1px solid var(--color-border)',
          boxShadow: 'var(--shadow-md)',
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Control Bar: Return to Findings List */}
        <div
          style={{
            padding: '0.875rem 1.5rem',
            borderBottom: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-surface-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <button
            onClick={handleClose}
            className="btn btn-secondary"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }}
            title="Return to findings explorer (preserves active filters)"
          >
            <ArrowLeft size={14} />
            <span>Back to Findings List</span>
          </button>

          <button
            onClick={handleClose}
            className="btn-icon"
            style={{ padding: '0.35rem' }}
            aria-label="Close detail panel"
          >
            <X size={18} />
          </button>
        </div>

        {/* Finding Header */}
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
          <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)', fontWeight: 600 }}>
              {finding.id}
            </span>
            <SeverityBadge severity={finding.severity} />
            <ConfidenceBadge confidence={finding.confidence} />
            <VerificationBadge status={finding.verification_status} />
            <span
              style={{
                fontSize: '0.72rem',
                color: 'var(--color-text-muted)',
                backgroundColor: 'var(--color-surface-subtle)',
                padding: '0.15rem 0.45rem',
                borderRadius: '3px',
                border: '1px solid var(--color-border)',
              }}
            >
              Origin: {finding.source_tool}
            </span>
          </div>

          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-text-main)', lineHeight: 1.3 }}>
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

        {/* Content Body */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          {/* Metadata Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '0.75rem',
              padding: '0.875rem 1rem',
              backgroundColor: 'var(--color-surface-subtle)',
              borderRadius: '4px',
              border: '1px solid var(--color-border)',
              fontSize: '0.8125rem',
            }}
          >
            <div>
              <span style={{ color: 'var(--color-text-dim)', display: 'block', fontSize: '0.7rem', fontWeight: 600 }}>
                AFFECTED ASSET
              </span>
              <span className="font-mono">{finding.asset_id || 'Global Target'}</span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-dim)', display: 'block', fontSize: '0.7rem', fontWeight: 600 }}>
                TAXONOMY (CWE / CVE)
              </span>
              <span>
                {finding.cwe || 'Unassigned'} {finding.cve ? `(${finding.cve})` : ''}
              </span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-dim)', display: 'block', fontSize: '0.7rem', fontWeight: 600 }}>
                FIRST OBSERVED
              </span>
              <span>{new Date(finding.first_seen).toLocaleString()}</span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-dim)', display: 'block', fontSize: '0.7rem', fontWeight: 600 }}>
                EVIDENCE PROOF COUNT
              </span>
              <span>{findingEvidence.length} record(s)</span>
            </div>
          </div>

          {/* Description */}
          <div>
            <h3 className="h3" style={{ marginBottom: '0.4rem' }}>
              Technical Description
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--color-text-main)', lineHeight: 1.6 }}>
              {finding.description}
            </p>
          </div>

          {/* SECTION 1: EMPIRICAL PROVENANCE & EVIDENCE */}
          <div
            style={{
              border: '1px solid var(--color-border)',
              borderRadius: '4px',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                padding: '0.75rem 1rem',
                backgroundColor: 'var(--color-surface-subtle)',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <FileCode size={15} style={{ color: 'var(--color-accent)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                Observed Facts & Captured Evidence (Provenance Layer)
              </span>
            </div>

            <div style={{ padding: '1rem' }}>
              {!hasEvidence ? (
                <div
                  style={{
                    padding: '1.25rem',
                    backgroundColor: 'var(--color-surface-subtle)',
                    border: '1px dashed var(--color-sev-medium-border)',
                    borderRadius: '4px',
                    textAlign: 'center',
                    color: 'var(--color-sev-medium-text)',
                    fontSize: '0.8125rem',
                    lineHeight: 1.6,
                  }}
                >
                  <AlertTriangle size={20} style={{ margin: '0 auto 0.4rem' }} />
                  <div>
                    <strong>EVIDENCE ABSENT:</strong> No raw scanner logs, HTTP payloads, or verification proofs are attached to this record.
                  </div>
                  <div style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem', marginTop: '0.2rem' }}>
                    System policy requires captured evidence before any candidate finding can be elevated to CONFIRMED.
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                  {findingEvidence.map((ev) => (
                    <div
                      key={ev.id}
                      style={{
                        border: '1px solid var(--color-border)',
                        borderRadius: '4px',
                        overflow: 'hidden',
                        backgroundColor: 'var(--color-surface)',
                      }}
                    >
                      <div
                        style={{
                          padding: '0.5rem 0.75rem',
                          backgroundColor: 'var(--color-surface-subtle)',
                          borderBottom: '1px solid var(--color-border)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          fontSize: '0.75rem',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className="font-mono" style={{ fontWeight: 700, color: 'var(--color-accent)' }}>
                            {ev.id}
                          </span>
                          <span style={{ color: 'var(--color-text-dim)' }}>·</span>
                          <span style={{ color: 'var(--color-text-muted)' }}>Collector: {ev.source}</span>
                          <span style={{ color: 'var(--color-text-dim)' }}>·</span>
                          <span style={{ color: 'var(--color-text-dim)' }}>{new Date(ev.observed_at).toLocaleTimeString()}</span>
                        </div>

                        {ev.raw_data && (
                          <button
                            onClick={() => handleCopyRaw(ev.id, ev.raw_data)}
                            className="btn btn-secondary"
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
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
                            style={{
                              fontSize: '0.72rem',
                              color: 'var(--color-text-dim)',
                              marginBottom: '0.5rem',
                              fontFamily: 'var(--font-mono)',
                            }}
                          >
                            Artifact Path: {ev.reference_or_artifact_location}
                          </div>
                        )}

                        {ev.raw_data && (
                          <pre
                            className="font-mono"
                            style={{
                              backgroundColor: 'var(--color-surface-subtle)',
                              padding: '0.75rem',
                              borderRadius: '4px',
                              border: '1px solid var(--color-border-subtle)',
                              fontSize: '0.75rem',
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

          {/* SECTION 2: AI ANALYSIS & TRIAGE (INFERENCE LAYER — VISIBLY SEPARATED) */}
          <div
            style={{
              border: '1px solid var(--color-border)',
              borderRadius: '4px',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                padding: '0.75rem 1rem',
                backgroundColor: 'var(--color-surface-subtle)',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <BrainCircuit size={15} style={{ color: 'var(--color-accent)' }} />
                <span style={{ fontSize: '0.8125rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                  AI Analysis & Triage (Inference Layer — Advisory Only)
                </span>
              </div>
              <span
                style={{
                  fontSize: '0.68rem',
                  color: 'var(--color-text-dim)',
                  backgroundColor: 'var(--color-surface)',
                  padding: '0.1rem 0.4rem',
                  borderRadius: '3px',
                  border: '1px solid var(--color-border)',
                }}
              >
                Model Advisory
              </span>
            </div>

            <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Mandatory Advisory Notice */}
              <div
                style={{
                  padding: '0.65rem 0.85rem',
                  backgroundColor: 'var(--color-surface-subtle)',
                  borderLeft: '3px solid var(--color-accent)',
                  borderRadius: '0 4px 4px 0',
                  fontSize: '0.75rem',
                  color: 'var(--color-text-muted)',
                  lineHeight: 1.5,
                }}
              >
                <strong>Inference Disclaimer:</strong> AI analysis provides automated risk correlation and remediation guidance based on supplied records. AI reasoning is strictly advisory and <em>does not confirm vulnerabilities independently of captured evidence</em>.
              </div>

              {!analysis ? (
                <div
                  style={{
                    padding: '1.5rem',
                    textAlign: 'center',
                    color: 'var(--color-text-dim)',
                    fontSize: '0.8125rem',
                  }}
                >
                  No AI analysis record generated for this finding yet.
                </div>
              ) : (
                <>
                  {/* Executive Summary */}
                  <div>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                      Executive Summary
                    </h4>
                    <p style={{ fontSize: '0.875rem', color: 'var(--color-text-main)', lineHeight: 1.5 }}>
                      {analysis.concise_summary}
                    </p>
                  </div>

                  {/* Empirical Reasoning */}
                  <div>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                      Grounded Technical Reasoning
                    </h4>
                    <div
                      style={{
                        padding: '0.85rem',
                        backgroundColor: 'var(--color-surface-subtle)',
                        borderRadius: '4px',
                        fontSize: '0.8125rem',
                        lineHeight: 1.6,
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {analysis.reasoning_summary}
                    </div>
                  </div>

                  {/* Severity & Confidence Justifications */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div style={{ padding: '0.75rem', border: '1px solid var(--color-border)', borderRadius: '4px' }}>
                      <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                        SEVERITY JUSTIFICATION ({analysis.severity_assessment.toUpperCase()})
                      </div>
                      <p style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>
                        {analysis.severity_justification}
                      </p>
                    </div>

                    <div style={{ padding: '0.75rem', border: '1px solid var(--color-border)', borderRadius: '4px' }}>
                      <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                        CONFIDENCE RATIONALE ({analysis.confidence_assessment.toUpperCase()})
                      </div>
                      <p style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>
                        {analysis.confidence_justification}
                      </p>
                    </div>
                  </div>

                  {/* Remediation */}
                  <div>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                      Actionable Remediation Guidance
                    </h4>
                    <pre
                      style={{
                        whiteSpace: 'pre-wrap',
                        fontFamily: 'inherit',
                        fontSize: '0.8125rem',
                        lineHeight: 1.6,
                        padding: '0.85rem',
                        backgroundColor: 'var(--color-surface-subtle)',
                        borderRadius: '4px',
                        border: '1px solid var(--color-border)',
                        color: 'var(--color-text-main)',
                      }}
                    >
                      {analysis.recommended_remediation}
                    </pre>
                  </div>

                  {/* Scope Limitations & Evidence Gaps */}
                  {analysis.limitations_and_missing_evidence.length > 0 && (
                    <div>
                      <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                        Documented Evidence Gaps & Limitations
                      </h4>
                      <ul style={{ paddingLeft: '1.25rem', fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.6 }}>
                        {analysis.limitations_and_missing_evidence.map((gap, i) => (
                          <li key={i}>{gap}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Cited Evidence IDs Grounding Check */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      fontSize: '0.75rem',
                      paddingTop: '0.5rem',
                      borderTop: '1px solid var(--color-border-subtle)',
                    }}
                  >
                    <span style={{ color: 'var(--color-text-dim)', fontWeight: 600 }}>CITED EVIDENCE IDS:</span>
                    {analysis.cited_evidence_ids.length === 0 ? (
                      <span style={{ color: 'var(--color-text-muted)', fontStyle: 'italic' }}>None (Zero empirical evidence cited)</span>
                    ) : (
                      analysis.cited_evidence_ids.map((id) => (
                        <span
                          key={id}
                          className="font-mono"
                          style={{
                            backgroundColor: 'var(--color-surface-subtle)',
                            padding: '0.1rem 0.4rem',
                            borderRadius: '3px',
                            border: '1px solid var(--color-border)',
                            color: 'var(--color-accent)',
                            fontWeight: 600,
                          }}
                        >
                          {id}
                        </span>
                      ))
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
