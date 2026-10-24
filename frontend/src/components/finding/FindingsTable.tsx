import React from 'react';
import type { Finding } from '../../types';
import { SeverityBadge, VerificationBadge, ConfidenceBadge } from '../Badge';
import { ArrowUpDown, AlertCircle, RotateCcw } from 'lucide-react';

interface FindingsTableProps {
  findings: Finding[];
  totalAssessmentFindingsCount: number;
  selectedFindingId: string | null;
  onSelectFinding: (id: string) => void;
  isLoading: boolean;
  sortBy: 'severity' | 'confidence' | 'title' | 'date';
  onToggleSort: (field: 'severity' | 'confidence' | 'title' | 'date') => void;
  isFilterActive: boolean;
  onResetFilters: () => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  totalAssessmentFindingsCount,
  selectedFindingId,
  onSelectFinding,
  isLoading,
  sortBy,
  onToggleSort,
  isFilterActive,
  onResetFilters,
}) => {
  return (
    <div className="table-container table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            {/* Severity Column Header with Sort */}
            <th
              className="cell-severity"
              style={{ cursor: 'pointer', userSelect: 'none' }}
              onClick={() => onToggleSort('severity')}
              title="Sort by Severity"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span>Severity</span>
                <ArrowUpDown
                  size={12}
                  style={{
                    color: sortBy === 'severity' ? 'var(--color-accent)' : 'var(--color-text-dim)',
                  }}
                />
              </div>
            </th>

            {/* Title & Description Column Header */}
            <th
              style={{ cursor: 'pointer', userSelect: 'none' }}
              onClick={() => onToggleSort('title')}
              title="Sort by Title"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span>Finding & Taxonomic Identity</span>
                <ArrowUpDown
                  size={12}
                  style={{
                    color: sortBy === 'title' ? 'var(--color-accent)' : 'var(--color-text-dim)',
                  }}
                />
              </div>
            </th>

            {/* Affected Asset */}
            <th style={{ width: '140px' }}>Target Asset</th>

            {/* Confidence Column Header with Sort */}
            <th
              style={{ width: '120px', cursor: 'pointer', userSelect: 'none' }}
              onClick={() => onToggleSort('confidence')}
              title="Sort by Confidence"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span>Confidence</span>
                <ArrowUpDown
                  size={12}
                  style={{
                    color: sortBy === 'confidence' ? 'var(--color-accent)' : 'var(--color-text-dim)',
                  }}
                />
              </div>
            </th>

            {/* Verification State */}
            <th style={{ width: '125px' }}>Verification</th>

            {/* Evidence References */}
            <th style={{ width: '110px' }}>Evidence Proof</th>

            {/* Source Tool */}
            <th style={{ width: '110px' }}>Source Tool</th>

            {/* Action */}
            <th className="cell-actions">Detail</th>
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            [1, 2, 3, 4, 5].map((idx) => (
              <tr key={`skeleton-${idx}`}>
                <td><span className="skeleton" style={{ width: '80px', height: '1.25rem' }} /></td>
                <td>
                  <span className="skeleton" style={{ width: '60%', height: '1rem', marginBottom: '6px' }} />
                  <span className="skeleton" style={{ width: '90%', height: '0.75rem' }} />
                </td>
                <td><span className="skeleton" style={{ width: '100px', height: '1rem' }} /></td>
                <td><span className="skeleton" style={{ width: '65px', height: '1.25rem' }} /></td>
                <td><span className="skeleton" style={{ width: '75px', height: '1.25rem' }} /></td>
                <td><span className="skeleton" style={{ width: '50px', height: '1rem' }} /></td>
                <td><span className="skeleton" style={{ width: '70px', height: '1rem' }} /></td>
                <td><span className="skeleton" style={{ width: '60px', height: '1.5rem' }} /></td>
              </tr>
            ))
          ) : findings.length === 0 ? (
            <tr>
              <td colSpan={8} style={{ textAlign: 'center', padding: '3.5rem 1rem' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
                  <AlertCircle size={28} style={{ color: 'var(--color-text-dim)' }} />
                  <div style={{ fontWeight: 600, color: 'var(--color-text-main)', fontSize: '0.95rem' }}>
                    {totalAssessmentFindingsCount === 0
                      ? 'No findings recorded for this assessment.'
                      : 'No findings match the active search and filter criteria.'}
                  </div>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', maxWidth: '400px' }}>
                    {totalAssessmentFindingsCount === 0
                      ? 'Run an authorized scan or import tool output to populate findings.'
                      : 'Try adjusting your search query, severity, or verification filter settings.'}
                  </div>
                  {isFilterActive && (
                    <button className="btn btn-secondary" onClick={onResetFilters} style={{ marginTop: '0.5rem' }}>
                      <RotateCcw size={13} />
                      <span>Reset All Filters</span>
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ) : (
            findings.map((finding) => {
              const isSelected = selectedFindingId === finding.id;
              const hasEvidence = finding.evidence_references && finding.evidence_references.length > 0;

              return (
                <tr
                  key={finding.id}
                  className={`clickable ${isSelected ? 'selected' : ''}`}
                  onClick={() => onSelectFinding(finding.id)}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectFinding(finding.id);
                    }
                  }}
                  aria-label={`Inspect finding: ${finding.title}`}
                >
                  {/* Severity Badge */}
                  <td className="w-severity cell-severity">
                    <SeverityBadge severity={finding.severity} />
                  </td>

                  {/* Title, Taxonomy, and Description snippet */}
                  <td>
                    <div style={{ fontWeight: 600 }}>
                      {finding.title}
                    </div>
                    <div className="row dim text-xs" style={{ gap: '0.5rem', marginTop: '2px' }}>
                      <span className="font-mono">{finding.id}</span>
                      {finding.cwe && <span className="font-mono">· {finding.cwe}</span>}
                      {finding.cve && <span className="font-mono">· {finding.cve}</span>}
                    </div>
                    <div className="muted text-xs truncate-1" style={{ marginTop: '4px' }}>
                      {finding.description}
                    </div>
                  </td>

                  {/* Affected Asset */}
                  <td className="font-mono text-sm">
                    {finding.asset_id || 'Global Target'}
                  </td>

                  {/* Confidence Badge */}
                  <td>
                    <ConfidenceBadge confidence={finding.confidence} />
                  </td>

                  {/* Verification Status */}
                  <td>
                    <VerificationBadge status={finding.verification_status} />
                  </td>

                  {/* Evidence Proof indicator */}
                  <td>
                    {hasEvidence ? (
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '0.72rem',
                          backgroundColor: 'var(--color-surface-hover)',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '3px',
                          border: '1px solid var(--color-border)',
                          color: 'var(--color-text-main)',
                          display: 'inline-block',
                        }}
                      >
                        {finding.evidence_references.length} proof item(s)
                      </span>
                    ) : (
                      <span
                        style={{
                          fontSize: '0.72rem',
                          color: 'var(--color-sev-medium-text)',
                          backgroundColor: 'var(--color-sev-medium-bg)',
                          border: '1px solid var(--color-sev-medium-border)',
                          padding: '0.1rem 0.35rem',
                          borderRadius: '3px',
                          fontWeight: 600,
                        }}
                      >
                        Missing
                      </span>
                    )}
                  </td>

                  {/* Origin Tool */}
                  <td style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>
                    {finding.source_tool}
                  </td>

                  {/* Detail Action */}
                  <td className="cell-actions">
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding(finding.id);
                      }}
                      aria-label={`Open details for ${finding.id}`}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
};
