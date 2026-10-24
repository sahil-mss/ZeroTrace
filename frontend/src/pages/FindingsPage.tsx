import React, { useState, useMemo } from 'react';
import { useApp } from '../context/useApp';
import { SeverityBadge, VerificationBadge, ConfidenceBadge } from '../components/Badge';
import {
  Search,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  RotateCcw,
} from 'lucide-react';
import type { FindingSeverity, ConfidenceLevel } from '../types';

const SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

const CONFIDENCE_WEIGHT: Record<ConfidenceLevel, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export const FindingsPage: React.FC = () => {
  const {
    findings,
    currentAssessmentId,
    selectedFindingId,
    setSelectedFindingId,
    globalSearch,
  } = useApp();

  // Filter States (preserved across selection / detail drawer)
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [verificationFilter, setVerificationFilter] = useState<string>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Sorting States
  const [sortBy, setSortBy] = useState<'severity' | 'confidence' | 'title' | 'date'>('severity');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  // Pagination for large datasets
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  // 1. Filter findings for current assessment
  const currentAssessmentFindings = useMemo(() => {
    return findings.filter((f) => f.assessment_id === currentAssessmentId);
  }, [findings, currentAssessmentId]);

  // 2. Multi-criteria filtering (search by title, asset, description, cwe, cve)
  const filteredFindings = useMemo(() => {
    return currentAssessmentFindings.filter((finding) => {
      // Severity Filter
      if (severityFilter !== 'all' && finding.severity !== severityFilter) return false;

      // Verification Filter
      if (verificationFilter !== 'all' && finding.verification_status !== verificationFilter)
        return false;

      // Confidence Filter
      if (confidenceFilter !== 'all' && finding.confidence !== confidenceFilter) return false;

      // Search Query (Title, Asset, Description, CWE, CVE, Tool)
      const query = (searchQuery || globalSearch).toLowerCase().trim();
      if (query) {
        const matchesTitle = finding.title.toLowerCase().includes(query);
        const matchesAsset = (finding.asset_id || '').toLowerCase().includes(query);
        const matchesDesc = finding.description.toLowerCase().includes(query);
        const matchesCwe = (finding.cwe || '').toLowerCase().includes(query);
        const matchesCve = (finding.cve || '').toLowerCase().includes(query);
        const matchesTool = finding.source_tool.toLowerCase().includes(query);

        if (!matchesTitle && !matchesAsset && !matchesDesc && !matchesCwe && !matchesCve && !matchesTool) {
          return false;
        }
      }

      return true;
    });
  }, [
    currentAssessmentFindings,
    severityFilter,
    verificationFilter,
    confidenceFilter,
    searchQuery,
    globalSearch,
  ]);

  // 3. Sorting (Severity, Confidence, Title, Date)
  const sortedFindings = useMemo(() => {
    const list = [...filteredFindings];
    list.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'severity') {
        comparison = SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
      } else if (sortBy === 'confidence') {
        comparison = CONFIDENCE_WEIGHT[a.confidence] - CONFIDENCE_WEIGHT[b.confidence];
      } else if (sortBy === 'title') {
        comparison = a.title.localeCompare(b.title);
      } else if (sortBy === 'date') {
        comparison = new Date(a.first_seen).getTime() - new Date(b.first_seen).getTime();
      }

      return sortOrder === 'desc' ? -comparison : comparison;
    });
    return list;
  }, [filteredFindings, sortBy, sortOrder]);

  // 4. Pagination
  const totalItems = sortedFindings.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedFindings.slice(start, start + pageSize);
  }, [sortedFindings, currentPage, pageSize]);

  const handleToggleSort = (field: 'severity' | 'confidence' | 'title' | 'date') => {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
    setCurrentPage(1);
  };

  const resetFilters = () => {
    setSeverityFilter('all');
    setVerificationFilter('all');
    setConfidenceFilter('all');
    setSearchQuery('');
    setCurrentPage(1);
  };

  const isFilterActive =
    severityFilter !== 'all' ||
    verificationFilter !== 'all' ||
    confidenceFilter !== 'all' ||
    searchQuery.trim().length > 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Page Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <h1 className="h1">Security Findings Explorer</h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Empirical findings triage with explicit distinction between impact severity, scanner confidence, and verification state.
          </p>
        </div>

        {/* Results Counter */}
        <div
          style={{
            fontSize: '0.75rem',
            color: 'var(--color-text-dim)',
            backgroundColor: 'var(--color-surface)',
            padding: '0.35rem 0.75rem',
            borderRadius: '4px',
            border: '1px solid var(--color-border)',
          }}
        >
          Showing <strong>{sortedFindings.length}</strong> of{' '}
          <strong>{currentAssessmentFindings.length}</strong> total findings
          {isFilterActive && <span style={{ color: 'var(--color-accent)', marginLeft: '4px' }}>(Filtered)</span>}
        </div>
      </div>

      {/* Control Bar: Search, Filters, Sorting */}
      <div
        className="panel"
        style={{
          padding: '0.875rem 1.25rem',
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.75rem',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        {/* Search Input */}
        <div style={{ position: 'relative', minWidth: '260px', flex: '1 1 280px' }}>
          <Search
            size={14}
            style={{
              position: 'absolute',
              left: '0.75rem',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--color-text-dim)',
            }}
          />
          <input
            type="text"
            className="input-text"
            placeholder="Search by title, asset, description, CWE..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            style={{ width: '100%', paddingLeft: '2.2rem' }}
            aria-label="Search findings by title, asset, and description"
          />
        </div>

        {/* Filters Group */}
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-text-dim)', fontWeight: 600 }}>SEVERITY:</span>
            <select
              className="input-select"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by severity"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>

          {/* Verification Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-text-dim)', fontWeight: 600 }}>VERIFICATION:</span>
            <select
              className="input-select"
              value={verificationFilter}
              onChange={(e) => {
                setVerificationFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by verification status"
            >
              <option value="all">All Statuses</option>
              <option value="confirmed">Confirmed</option>
              <option value="likely">Likely</option>
              <option value="unverified">Unverified</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          {/* Confidence Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-text-dim)', fontWeight: 600 }}>CONFIDENCE:</span>
            <select
              className="input-select"
              value={confidenceFilter}
              onChange={(e) => {
                setConfidenceFilter(e.target.value);
                setCurrentPage(1);
              }}
              aria-label="Filter by confidence"
            >
              <option value="all">All Confidence</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Reset Filters Button */}
          {isFilterActive && (
            <button
              className="btn btn-secondary"
              onClick={resetFilters}
              style={{ padding: '0.45rem 0.65rem', fontSize: '0.75rem' }}
              title="Reset all search queries and filters"
            >
              <RotateCcw size={12} />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Findings Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              {/* Severity Column Header with Sort */}
              <th
                style={{ width: '135px', cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleToggleSort('severity')}
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
                onClick={() => handleToggleSort('title')}
                title="Sort by Title"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span>Vulnerability & Context</span>
                  <ArrowUpDown
                    size={12}
                    style={{
                      color: sortBy === 'title' ? 'var(--color-accent)' : 'var(--color-text-dim)',
                    }}
                  />
                </div>
              </th>

              {/* Affected Asset */}
              <th style={{ width: '160px' }}>Affected Asset</th>

              {/* Confidence Column (Distinct from Severity) */}
              <th
                style={{ width: '130px', cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleToggleSort('confidence')}
                title="Sort by Confidence Level"
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

              {/* Verification Status */}
              <th style={{ width: '140px' }}>Verification Status</th>

              {/* Evidence References */}
              <th style={{ width: '110px' }}>Evidence Proof</th>

              {/* Source Tool */}
              <th style={{ width: '110px' }}>Source Tool</th>

              {/* Action */}
              <th style={{ width: '90px' }}>Detail</th>
            </tr>
          </thead>
          <tbody>
            {paginatedFindings.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '3.5rem 1rem' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
                    <AlertCircle size={28} style={{ color: 'var(--color-text-dim)' }} />
                    <div style={{ fontWeight: 600, color: 'var(--color-text-main)', fontSize: '0.95rem' }}>
                      {currentAssessmentFindings.length === 0
                        ? 'No findings recorded for this assessment.'
                        : 'No findings match the active search and filter criteria.'}
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', maxWidth: '400px' }}>
                      {currentAssessmentFindings.length === 0
                        ? 'Run an authorized scan or import tool output to populate findings.'
                        : 'Try adjusting your search query, severity, or verification filter settings.'}
                    </div>
                    {isFilterActive && (
                      <button className="btn btn-secondary" onClick={resetFilters} style={{ marginTop: '0.5rem' }}>
                        <RotateCcw size={13} />
                        <span>Reset All Filters</span>
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              paginatedFindings.map((finding) => {
                const isSelected = selectedFindingId === finding.id;
                const hasEvidence = finding.evidence_references && finding.evidence_references.length > 0;

                return (
                  <tr
                    key={finding.id}
                    className={`clickable ${isSelected ? 'selected' : ''}`}
                    onClick={() => setSelectedFindingId(finding.id)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelectedFindingId(finding.id);
                      }
                    }}
                    aria-label={`Inspect finding: ${finding.title}`}
                  >
                    {/* Severity Badge */}
                    <td>
                      <SeverityBadge severity={finding.severity} />
                    </td>

                    {/* Title, Taxonomy, and Description snippet */}
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--color-text-main)', fontSize: '0.875rem' }}>
                        {finding.title}
                      </div>
                      <div
                        style={{
                          fontSize: '0.72rem',
                          color: 'var(--color-text-dim)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          marginTop: '2px',
                        }}
                      >
                        <span className="font-mono">{finding.id}</span>
                        {finding.cwe && <span className="font-mono">· {finding.cwe}</span>}
                        {finding.cve && <span className="font-mono">· {finding.cve}</span>}
                      </div>
                      <div
                        style={{
                          fontSize: '0.78rem',
                          color: 'var(--color-text-muted)',
                          marginTop: '4px',
                          display: '-webkit-box',
                          WebkitLineClamp: 1,
                          WebkitBoxOrient: 'vertical',
                          overflow: 'hidden',
                        }}
                      >
                        {finding.description}
                      </div>
                    </td>

                    {/* Affected Asset */}
                    <td className="font-mono" style={{ fontSize: '0.78rem' }}>
                      {finding.asset_id || 'Global Target'}
                    </td>

                    {/* Confidence Badge (Visibly separated from severity) */}
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
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFindingId(finding.id);
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

      {/* Pagination Controls for Large Datasets */}
      {totalPages > 1 && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.5rem 0.25rem',
            fontSize: '0.8125rem',
            color: 'var(--color-text-muted)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>Items per page:</span>
            <select
              className="input-select"
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
            >
              <option value={5}>5</option>
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              className="btn btn-secondary"
              style={{ padding: '0.3rem 0.6rem' }}
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              aria-label="Previous page"
            >
              <ChevronLeft size={14} />
            </button>
            <button
              className="btn btn-secondary"
              style={{ padding: '0.3rem 0.6rem' }}
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              aria-label="Next page"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
