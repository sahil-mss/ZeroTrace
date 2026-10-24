import React, { useState } from 'react';
import { useApp } from '../context/useApp';
import { useFocusTrap } from './useFocusTrap';
import { X, ArrowLeft } from 'lucide-react';
import { apiClient } from '../api/client';
import { FindingHeader } from './finding/FindingHeader';
import { EvidencePanel } from './finding/EvidencePanel';
import { AIAnalysisPanel } from './finding/AIAnalysisPanel';
import { RemediationSection } from './finding/RemediationSection';

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

  const handleClose = () => {
    setSelectedFindingId(null);
  };

  const focusTrapRef = useFocusTrap({
    isOpen: Boolean(selectedFindingId),
    onClose: handleClose,
  });

  if (!selectedFindingId) return null;

  const finding = findings.find((f) => f.id === selectedFindingId);
  if (!finding) return null;

  const analysis = aiAnalysis[finding.id];

  const handleCopyRaw = (evId: string, text?: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedEvidenceId(evId);
    addToast('Payload Copied', `Evidence snippet ${evId} copied to clipboard`, 'info');
    setTimeout(() => setCopiedEvidenceId(null), 2000);
  };

  const handleAnalyzeFinding = async () => {
    setIsAnalyzing(true);
    setAnalysisError(null);

    const relatedEvidence = evidence.filter((ev) =>
      finding.evidence_references.includes(ev.id)
    );

    try {
      const result = await apiClient.analyzeFinding(finding, relatedEvidence);
      updateFindingAnalysis(finding.id, result);
      addToast('AI Analysis Complete', `Grounded triage generated for ${finding.id}`, 'success');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown network failure';
      setAnalysisError(message);
      addToast('Analysis Error', message, 'error');
    } finally {
      setIsAnalyzing(false);
    }
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
      aria-labelledby="finding-detail-title"
    >
      <div
        ref={focusTrapRef}
        tabIndex={-1}
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
          outline: 'none',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Control Bar: Return to Findings List */}
        <div
          className="row-between"
          style={{
            padding: '0.875rem 1.5rem',
            borderBottom: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-surface-subtle)',
          }}
        >
          <button
            onClick={handleClose}
            className="btn btn-secondary btn-xs"
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

        {/* Finding Header with badge cluster & status banner */}
        <FindingHeader finding={finding} />

        {/* Content Body */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          {/* Metadata Grid */}
          <div
            className="grid-4 responsive-grid"
            style={{
              padding: '1rem',
              backgroundColor: 'var(--color-surface-subtle)',
              borderRadius: '4px',
              border: '1px solid var(--color-border)',
            }}
          >
            <div>
              <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Target Asset</div>
              <div className="font-mono text-sm" style={{ fontWeight: 600, marginTop: '0.2rem' }}>
                {finding.asset_id || 'Target Scope'}
              </div>
            </div>
            <div>
              <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Taxonomy / CWE</div>
              <div className="font-mono text-sm" style={{ marginTop: '0.2rem' }}>
                {finding.cwe || 'None'} {finding.cve ? `(${finding.cve})` : ''}
              </div>
            </div>
            <div>
              <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Source Scanner</div>
              <div className="text-sm" style={{ marginTop: '0.2rem' }}>
                {finding.source_tool}
              </div>
            </div>
            <div>
              <div className="dim text-xs" style={{ fontWeight: 600, textTransform: 'uppercase' }}>Empirical Evidence</div>
              <div className="text-sm" style={{ marginTop: '0.2rem', fontWeight: 600, color: 'var(--color-accent)' }}>
                {finding.evidence_references.length} record(s) linked
              </div>
            </div>
          </div>

          {/* Detailed Vulnerability Description */}
          <div>
            <h3 className="dim text-xs" style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.5rem' }}>
              Vulnerability Description
            </h3>
            <p className="muted text-sm" style={{ lineHeight: 1.6, margin: 0 }}>
              {finding.description}
            </p>
          </div>

          {/* Empirical Evidence Records Panel */}
          <EvidencePanel
            finding={finding}
            evidence={evidence}
            copiedEvidenceId={copiedEvidenceId}
            onCopyRaw={handleCopyRaw}
          />

          {/* AI Analysis & Triage Panel */}
          <AIAnalysisPanel
            finding={finding}
            analysis={analysis}
            isAnalyzing={isAnalyzing}
            analysisError={analysisError}
            onAnalyze={handleAnalyzeFinding}
          />

          {/* Deterministic Remediation Guidance */}
          <RemediationSection finding={finding} />
        </div>
      </div>
    </div>
  );
};
