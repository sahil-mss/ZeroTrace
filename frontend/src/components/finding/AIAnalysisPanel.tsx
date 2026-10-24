import React from 'react';
import type { Finding, AIAnalysis } from '../../types';
import { SeverityBadge, ConfidenceBadge } from '../Badge';
import { BrainCircuit, Loader2, RefreshCw, AlertTriangle, Cpu } from 'lucide-react';

interface AIAnalysisPanelProps {
  finding: Finding;
  analysis?: AIAnalysis;
  isAnalyzing: boolean;
  analysisError: string | null;
  onAnalyze: () => void;
}

export const AIAnalysisPanel: React.FC<AIAnalysisPanelProps> = ({
  finding,
  analysis,
  isAnalyzing,
  analysisError,
  onAnalyze,
}) => {
  const isUnverified = finding.verification_status === 'unverified';

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
          <BrainCircuit size={15} style={{ color: 'var(--color-accent)' }} />
          <span style={{ fontSize: '0.8125rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            AI Analysis & Triage (Inference Layer — Advisory Only)
          </span>
        </div>

        <div className="row">
          {analysis && (
            <div
              className="row font-mono text-xs muted subtle-box"
              style={{ padding: '0.2rem 0.5rem' }}
            >
              <Cpu size={12} />
              <span>Engine: {analysis.analysis_provider || 'ZeroTrace Intelligence'}</span>
            </div>
          )}

          <button
            onClick={onAnalyze}
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
                <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} />
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

      <div
        style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}
        aria-busy={isAnalyzing}
        aria-live="polite"
      >
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
            className="row-between"
            style={{
              padding: '0.75rem 1rem',
              backgroundColor: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid var(--color-sev-critical-border)',
              borderRadius: '4px',
              alignItems: 'flex-start',
            }}
          >
            <div className="row" style={{ alignItems: 'flex-start', gap: '0.6rem' }}>
              <AlertTriangle size={18} style={{ color: 'var(--color-sev-critical)', flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-sev-critical)' }}>
                  Analysis Request Failed
                </div>
                <div className="muted text-xs" style={{ marginTop: '0.2rem' }}>
                  {analysisError}
                </div>
              </div>
            </div>

            <button
              onClick={onAnalyze}
              className="btn btn-secondary btn-xs"
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
            <div className="muted text-xs" style={{ textAlign: 'center', maxWidth: '420px' }}>
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
            <BrainCircuit size={28} className="dim" />
            <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-main)' }}>
              No AI Analysis Generated Yet
            </div>
            <p className="muted text-xs" style={{ maxWidth: '450px', margin: 0 }}>
              Select &quot;Analyze Finding&quot; to invoke the evidence-grounded AI analysis engine. The engine will synthesize empirical evidence facts, deduce technical impact, and propose remediation without hallucination.
            </p>
            <button
              onClick={onAnalyze}
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
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  fontSize: '0.75rem',
                  color: 'var(--color-sev-medium-text)',
                }}
              >
                <AlertTriangle size={15} style={{ flexShrink: 0 }} />
                <span>
                  <strong>Advisory Warning:</strong> This finding is unverified. Scanner alerts may represent heuristic false flags. Empirical reproduction should be prioritized.
                </span>
              </div>
            )}

            {/* 1. Executive Interpretation & Summary */}
            <div>
              <h4 className="dim text-xs" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                Executive Interpretation & Root Cause Analysis
              </h4>
              <p
                data-testid="analysis-summary"
                style={{
                  fontSize: '0.8125rem',
                  lineHeight: 1.6,
                  color: 'var(--color-text-main)',
                  backgroundColor: 'var(--color-surface-subtle)',
                  padding: '0.75rem 1rem',
                  borderRadius: '4px',
                  border: '1px solid var(--color-border-subtle)',
                  margin: 0,
                }}
              >
                {analysis.summary || 'No summary produced by analysis model.'}
              </p>
            </div>

            {/* 2. Synthesized Evidence Facts */}
            {analysis.evidence_facts && analysis.evidence_facts.length > 0 && (
              <div>
                <h4 className="dim text-xs" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                  Empirical Evidence Facts (Synthesized from Proof Records)
                </h4>
                <ul
                  data-testid="analysis-evidence-facts"
                  className="muted text-sm"
                  style={{ paddingLeft: '1.25rem', lineHeight: 1.6, margin: 0 }}
                >
                  {analysis.evidence_facts.map((fact, idx) => (
                    <li key={idx} style={{ marginBottom: '0.25rem' }}>{fact}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* 3. Reasoned Technical Interpretation */}
            <div>
              <h4 className="dim text-xs" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                Technical Deductions & Security Impact
              </h4>
              <div
                data-testid="analysis-reasoning"
                className="muted text-sm"
                style={{ lineHeight: 1.6 }}
              >
                {analysis.interpretation && analysis.interpretation.length > 0 ? (
                  <ul style={{ paddingLeft: '1.25rem', margin: 0 }}>
                    {analysis.interpretation.map((item, idx) => (
                      <li key={idx} style={{ marginBottom: '0.25rem' }}>{item}</li>
                    ))}
                  </ul>
                ) : (
                  <p style={{ margin: 0 }}>{analysis.reasoning_summary || 'No detailed interpretation recorded.'}</p>
                )}
              </div>
            </div>

            {/* 4. Severity & Confidence with Grounded Justifications */}
            <div className="modal-side-by-side" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <div style={{ padding: '0.75rem', border: '1px solid var(--color-border)', borderRadius: '4px' }}>
                <div className="row-between" style={{ marginBottom: '0.35rem' }}>
                  <span className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
                    Assessed Severity
                  </span>
                  <SeverityBadge severity={analysis.severity || analysis.severity_assessment || finding.severity} />
                </div>
                <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                  Severity Justification
                </div>
                <p data-testid="analysis-severity-justification" className="muted text-xs" style={{ lineHeight: 1.5, margin: 0 }}>
                  {analysis.severity_justification}
                </p>
              </div>

              <div style={{ padding: '0.75rem', border: '1px solid var(--color-border)', borderRadius: '4px' }}>
                <div className="row-between" style={{ marginBottom: '0.35rem' }}>
                  <span className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>
                    Confidence Level
                  </span>
                  <ConfidenceBadge confidence={analysis.confidence || analysis.confidence_assessment || finding.confidence} />
                </div>
                <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                  Confidence Justification
                </div>
                <p data-testid="analysis-confidence-justification" className="muted text-xs" style={{ lineHeight: 1.5, margin: 0 }}>
                  {analysis.confidence_justification}
                </p>
              </div>
            </div>

            {/* 5. Remediation Roadmap */}
            <div>
              <h4 className="dim text-xs" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                Prioritized Remediation Roadmap
              </h4>
              <div
                data-testid="analysis-remediation"
                style={{
                  backgroundColor: 'var(--color-surface-subtle)',
                  padding: '0.85rem 1rem',
                  borderRadius: '4px',
                  border: '1px solid var(--color-border-subtle)',
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
                <h4 className="dim text-xs" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                  Limitations & Information Still Needed
                </h4>
                <ul
                  data-testid="analysis-limitations"
                  className="muted text-sm"
                  style={{ paddingLeft: '1.25rem', lineHeight: 1.6, margin: 0 }}
                >
                  {(analysis.limitations || analysis.limitations_and_missing_evidence || []).map((gap, i) => (
                    <li key={i} style={{ marginBottom: '0.25rem' }}>{gap}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Cited Evidence IDs Grounding Check */}
            <div
              className="row font-mono text-xs"
              style={{
                gap: '0.5rem',
                paddingTop: '0.5rem',
                borderTop: '1px solid var(--color-border-subtle)',
              }}
            >
              <span className="dim" style={{ fontWeight: 600 }}>CITED EVIDENCE IDS:</span>
              {(!analysis.cited_evidence_ids || analysis.cited_evidence_ids.length === 0) ? (
                <span className="muted" style={{ fontStyle: 'italic' }}>None (Zero empirical evidence cited)</span>
              ) : (
                analysis.cited_evidence_ids.map((id) => (
                  <span
                    key={id}
                    className="status-pill pill-accent font-mono"
                    style={{ border: '1px solid var(--color-border)' }}
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
  );
};
