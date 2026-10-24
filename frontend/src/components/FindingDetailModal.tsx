import React, { useState } from 'react';
import { useApp } from '../context/useApp';
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
  Loader2,
  RefreshCw,
  Cpu,
  ShieldAlert,
} from 'lucide-react';
import { SeverityBadge, VerificationBadge, ConfidenceBadge } from './Badge';
import { apiClient } from '../api/client';

export const FindingDetailModal: React.FC = () => {
  const {
    selectedFindingId,
    setSelectedFindingId,
    findings,
    evidence,
    aiAnalysis,
    updateFindingAnalysis,
    addToast,
  } = useApp();

  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  if (!selectedFindingId) return null;

  const finding = findings.find((f) => f.id === selectedFindingId);
  if (!finding) return null;

  const findingEvidence = evidence.filter((ev) => finding.evidence_references.includes(ev.id));
  const analysis = aiAnalysis[finding.id];
  const isUnverified = finding.verification_status === 'unverified';
  const isFalsePositive = finding.verification_status === 'false_positive';
  const isConfirmed = finding.verification_status === 'confirmed';
  const hasEvidence = findingEvidence.length > 0;

  const handleAnalyzeFinding = async () => {
    if (isAnalyzing) return; // Prevent duplicate concurrent submissions
    setIsAnalyzing(true);
    setAnalysisError(null);

    try {
      const result = await apiClient.analyzeFinding(finding, findingEvidence);
      updateFindingAnalysis(finding.id, result);
      addToast(
        'Analysis Complete',
        `Generated structured AI triage for ${finding.id}`,
        'success'
      );
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error during AI analysis';
      setAnalysisError(message);
      addToast('Analysis Failed', message, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

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
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <BrainCircuit size={15} style={{ color: 'var(--color-accent)' }} />
                <span style={{ fontSize: '0.8125rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                  AI Analysis & Triage (Inference Layer — Advisory Only)
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {/* Source Attribution Badge */}
                {analysis && (
                  <span
                    data-testid="analysis-source-badge"
                    style={{
                      fontSize: '0.68rem',
                      color: analysis.is_rule_based_fallback ? 'var(--color-sev-medium)' : 'var(--color-accent)',
                      backgroundColor: 'var(--color-surface)',
                      padding: '0.15rem 0.45rem',
                      borderRadius: '3px',
                      border: '1px solid var(--color-border)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                      fontWeight: 600,
                    }}
                  >
                    <Cpu size={12} />
                    {analysis.is_rule_based_fallback
                      ? `Deterministic Rule-Based Fallback (${analysis.analysis_provider || 'Non-LLM'})`
                      : `Configured Model (${analysis.analysis_provider || 'LLM'})`}
                  </span>
                )}

                {/* Analyze Finding Button */}
                <button
                  onClick={handleAnalyzeFinding}
                  disabled={isAnalyzing}
                  className="btn btn-primary"
                  style={{
                    padding: '0.3rem 0.75rem',
                    fontSize: '0.75rem',
                    opacity: isAnalyzing ? 0.7 : 1,
                    cursor: isAnalyzing ? 'not-allowed' : 'pointer',
                  }}
                  data-testid="analyze-finding-button"
                  title="Run grounded AI triage against backend service"
                >
                  {isAnalyzing ? (
                    <>
                      <Loader2 size={13} className="spin-animation" style={{ animation: 'spin 1s linear infinite' }} />
                      <span>Analyzing Finding...</span>
                    </>
                  ) : (
                    <>
                      <BrainCircuit size={13} />
                      <span>{analysis ? 'Re-analyze Finding' : 'Analyze Finding'}</span>
                    </>
                  )}
                </button>
              </div>
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

              {/* Error State with Retry Action */}
              {analysisError && (
                <div
                  data-testid="analysis-error-banner"
                  style={{
                    padding: '0.75rem 1rem',
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    border: '1px solid var(--color-sev-critical-border)',
                    borderRadius: '4px',
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    gap: '1rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.6rem' }}>
                    <AlertTriangle size={18} style={{ color: 'var(--color-sev-critical)', flexShrink: 0, marginTop: '2px' }} />
                    <div>
                      <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-sev-critical)' }}>
                        Analysis Request Failed
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                        {analysisError}
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={handleAnalyzeFinding}
                    disabled={isAnalyzing}
                    className="btn btn-secondary"
                    style={{ padding: '0.25rem 0.65rem', fontSize: '0.72rem', flexShrink: 0 }}
                    data-testid="retry-analysis-button"
                  >
                    <RefreshCw size={12} />
                    <span>Retry Analysis</span>
                  </button>
                </div>
              )}

              {/* Loading State Spinner */}
              {isAnalyzing && (
                <div
                  data-testid="analysis-loading-state"
                  style={{
                    padding: '2.5rem 1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.75rem',
                    backgroundColor: 'var(--color-surface-subtle)',
                    borderRadius: '4px',
                    border: '1px dashed var(--color-border)',
                  }}
                >
                  <Loader2 size={28} style={{ color: 'var(--color-accent)', animation: 'spin 1s linear infinite' }} />
                  <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-main)' }}>
                    Generating Evidence-Grounded AI Triage
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', textAlign: 'center', maxWidth: '420px' }}>
                    Validating citations against captured scanner logs, applying anti-hallucination guardrails, and formulating remediation roadmap.
                  </div>
                </div>
              )}

              {!isAnalyzing && !analysis && (
                <div
                  data-testid="analysis-empty-state"
                  style={{
                    padding: '2rem 1.5rem',
                    textAlign: 'center',
                    backgroundColor: 'var(--color-surface-subtle)',
                    borderRadius: '4px',
                    border: '1px dashed var(--color-border)',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '0.6rem',
                  }}
                >
                  <BrainCircuit size={28} style={{ color: 'var(--color-text-dim)' }} />
                  <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-main)' }}>
                    No AI Analysis Generated Yet
                  </div>
                  <p style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', maxWidth: '450px', margin: 0 }}>
                    Select &quot;Analyze Finding&quot; to invoke the evidence-grounded AI analysis engine. The engine will synthesize empirical evidence facts, deduce technical impact, and propose remediation without hallucination.
                  </p>
                  <button
                    onClick={handleAnalyzeFinding}
                    className="btn btn-primary"
                    style={{ padding: '0.4rem 0.9rem', fontSize: '0.78rem', marginTop: '0.4rem' }}
                  >
                    <BrainCircuit size={13} />
                    <span>Analyze finding</span>
                  </button>
                </div>
              )}

              {!isAnalyzing && analysis && (
                <div data-testid="analysis-results-container" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {/* Verification Status Warning when Unverified */}
                  {isUnverified && (
                    <div
                      style={{
                        padding: '0.65rem 0.85rem',
                        backgroundColor: 'var(--color-sev-medium-bg)',
                        border: '1px solid var(--color-sev-medium-border)',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.6rem',
                      }}
                    >
                      <ShieldAlert size={16} style={{ color: 'var(--color-sev-medium)', flexShrink: 0 }} />
                      <div>
                        <strong>Verification Policy Notice:</strong> This finding has not undergone empirical exploit verification. In accordance with zero-trust AI rules, AI reasoning does <em>not</em> confirm this vulnerability.
                      </div>
                    </div>
                  )}

                  {/* 1. Summary */}
                  <div>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                      Summary
                    </h4>
                    <p data-testid="analysis-summary" style={{ fontSize: '0.875rem', color: 'var(--color-text-main)', lineHeight: 1.5 }}>
                      {analysis.summary || analysis.concise_summary}
                    </p>
                  </div>

                  {/* 2. Evidence Facts Observed */}
                  {((analysis.evidence_facts && analysis.evidence_facts.length > 0) || !hasEvidence) && (
                    <div>
                      <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                        Evidence Facts Observed
                      </h4>
                      {analysis.evidence_facts && analysis.evidence_facts.length > 0 ? (
                        <ul data-testid="analysis-evidence-facts" style={{ paddingLeft: '1.25rem', fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.6 }}>
                          {analysis.evidence_facts.map((fact, idx) => (
                            <li key={idx} style={{ marginBottom: '0.25rem' }}>{fact}</li>
                          ))}
                        </ul>
                      ) : (
                        <div style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', fontStyle: 'italic', padding: '0.5rem', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px' }}>
                          No empirical evidence facts captured. Verification probe recommended.
                        </div>
                      )}
                    </div>
                  )}

                  {/* 3. AI Interpretation */}
                  <div>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                      AI Interpretation & Root Cause Analysis
                    </h4>
                    <div
                      data-testid="analysis-interpretation"
                      style={{
                        padding: '0.85rem',
                        backgroundColor: 'var(--color-surface-subtle)',
                        borderRadius: '4px',
                        fontSize: '0.8125rem',
                        lineHeight: 1.6,
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {analysis.interpretation && analysis.interpretation.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                          {analysis.interpretation.map((interp, idx) => (
                            <p key={idx} style={{ margin: 0 }}>{interp}</p>
                          ))}
                        </div>
                      ) : (
                        <p style={{ margin: 0 }}>{analysis.reasoning_summary || 'No detailed interpretation recorded.'}</p>
                      )}
                    </div>
                  </div>

                  {/* 4. Severity & Confidence with Grounded Justifications */}
                  <div className="modal-side-by-side" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div style={{ padding: '0.75rem', border: '1px solid var(--color-border)', borderRadius: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                        <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>
                          Assessed Severity
                        </span>
                        <SeverityBadge severity={analysis.severity || analysis.severity_assessment || finding.severity} />
                      </div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                        Severity Justification
                      </div>
                      <p data-testid="analysis-severity-justification" style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', lineHeight: 1.5, margin: 0 }}>
                        {analysis.severity_justification}
                      </p>
                    </div>

                    <div style={{ padding: '0.75rem', border: '1px solid var(--color-border)', borderRadius: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                        <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase' }}>
                          Confidence Level
                        </span>
                        <ConfidenceBadge confidence={analysis.confidence || analysis.confidence_assessment || finding.confidence} />
                      </div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                        Confidence Justification
                      </div>
                      <p data-testid="analysis-confidence-justification" style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', lineHeight: 1.5, margin: 0 }}>
                        {analysis.confidence_justification}
                      </p>
                    </div>
                  </div>

                  {/* 5. Remediation Steps */}
                  <div>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                      Prioritized Remediation Roadmap
                    </h4>
                    <div
                      data-testid="analysis-remediation"
                      style={{
                        padding: '0.85rem',
                        backgroundColor: 'var(--color-surface-subtle)',
                        borderRadius: '4px',
                        border: '1px solid var(--color-border)',
                        color: 'var(--color-text-main)',
                        fontSize: '0.8125rem',
                        lineHeight: 1.6,
                      }}
                    >
                      {analysis.remediation && analysis.remediation.length > 0 ? (
                        <ol style={{ paddingLeft: '1.25rem', margin: 0 }}>
                          {analysis.remediation.map((step, idx) => (
                            <li key={idx} style={{ marginBottom: '0.35rem' }}>{step}</li>
                          ))}
                        </ol>
                      ) : (
                        <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', margin: 0 }}>
                          {analysis.recommended_remediation || finding.remediation || 'Apply standard patch and hardening guidelines.'}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* 6. Limitations / Information Still Needed */}
                  {((analysis.limitations && analysis.limitations.length > 0) ||
                    (analysis.limitations_and_missing_evidence && analysis.limitations_and_missing_evidence.length > 0)) && (
                    <div>
                      <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-dim)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                        Limitations & Information Still Needed
                      </h4>
                      <ul
                        data-testid="analysis-limitations"
                        style={{ paddingLeft: '1.25rem', fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.6, margin: 0 }}
                      >
                        {(analysis.limitations || analysis.limitations_and_missing_evidence || []).map((gap, i) => (
                          <li key={i} style={{ marginBottom: '0.25rem' }}>{gap}</li>
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
                    {(!analysis.cited_evidence_ids || analysis.cited_evidence_ids.length === 0) ? (
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
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
