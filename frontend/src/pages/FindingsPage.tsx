import React, { useState, useMemo } from 'react';
import { useApp } from '../context/useApp';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { FindingSeverity, ConfidenceLevel } from '../types';
import { FindingsFilterBar } from '../components/finding/FindingsFilterBar';
import { FindingsTable } from '../components/finding/FindingsTable';

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
    isBackendHealthy,
    isLoading,
  } = useApp();

  const isDemo = isBackendHealthy === false;

  // Filter States
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
      if (severityFilter !== 'all' && finding.severity !== severityFilter) return false;
      if (verificationFilter !== 'all' && finding.verification_status !== verificationFilter) return false;
      if (confidenceFilter !== 'all' && finding.confidence !== confidenceFilter) return false;

      const query = (searchQuery || globalSearch).toLowerCase().trim();
      if (!query) return true;

      const titleMatch = finding.title.toLowerCase().includes(query);
      const descMatch = finding.description.toLowerCase().includes(query);
      const assetMatch = (finding.asset_id || '').toLowerCase().includes(query);
      const cweMatch = (finding.cwe || '').toLowerCase().includes(query);
      const cveMatch = (finding.cve || '').toLowerCase().includes(query);
      const toolMatch = finding.source_tool.toLowerCase().includes(query);

      return titleMatch || descMatch || assetMatch || cweMatch || cveMatch || toolMatch;
    });
  }, [currentAssessmentFindings, severityFilter, verificationFilter, confidenceFilter, searchQuery, globalSearch]);

  // 3. Sorting logic
  const sortedFindings = useMemo(() => {
    const list = [...filteredFindings];
    list.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'severity') {
        comparison = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
      } else if (sortBy === 'confidence') {
        comparison = CONFIDENCE_WEIGHT[b.confidence] - CONFIDENCE_WEIGHT[a.confidence];
      } else if (sortBy === 'title') {
        comparison = a.title.localeCompare(b.title);
      } else if (sortBy === 'date') {
        comparison = new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime();
      }
      return sortOrder === 'asc' ? -comparison : comparison;
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
    <div className="stack">
      {/* Page Header */}
      <div className="row-between responsive-stack">
        <div>
          <div className="row" style={{ alignItems: 'center', gap: '0.5rem' }}>
            <h1 className="h1" style={{ margin: 0 }}>Security Findings Explorer</h1>
            {isDemo && <span className="demo-data-tag">DEMO DATA</span>}
          </div>
          <p className="muted text-sm" style={{ marginTop: '0.2rem' }}>
            Empirical findings triage with explicit distinction between impact severity, scanner confidence, and verification state.
          </p>
        </div>

        {/* Results Counter */}
        <div className="subtle-box text-xs dim" style={{ padding: '0.35rem 0.75rem' }}>
          Showing <strong>{sortedFindings.length}</strong> of{' '}
          <strong>{currentAssessmentFindings.length}</strong> total findings
          {isFilterActive && <span style={{ color: 'var(--color-accent)', marginLeft: '4px' }}>(Filtered)</span>}
        </div>
      </div>

      {/* Control Bar: Search, Filters */}
      <FindingsFilterBar
        searchQuery={searchQuery}
        setSearchQuery={(val) => {
          setSearchQuery(val);
          setCurrentPage(1);
        }}
        severityFilter={severityFilter}
        setSeverityFilter={(val) => {
          setSeverityFilter(val);
          setCurrentPage(1);
        }}
        verificationFilter={verificationFilter}
        setVerificationFilter={(val) => {
          setVerificationFilter(val);
          setCurrentPage(1);
        }}
        confidenceFilter={confidenceFilter}
        setConfidenceFilter={(val) => {
          setConfidenceFilter(val);
          setCurrentPage(1);
        }}
        isFilterActive={isFilterActive}
        onResetFilters={resetFilters}
      />

      {/* Findings Table */}
      <FindingsTable
        findings={paginatedFindings}
        totalAssessmentFindingsCount={currentAssessmentFindings.length}
        selectedFindingId={selectedFindingId}
        onSelectFinding={(id) => setSelectedFindingId(id)}
        isLoading={isLoading}
        sortBy={sortBy}
        onToggleSort={handleToggleSort}
        isFilterActive={isFilterActive}
        onResetFilters={resetFilters}
      />

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
