import React from 'react';
import { Search, RotateCcw } from 'lucide-react';

interface FindingsFilterBarProps {
  searchQuery: string;
  setSearchQuery: (val: string) => void;
  severityFilter: string;
  setSeverityFilter: (val: string) => void;
  verificationFilter: string;
  setVerificationFilter: (val: string) => void;
  confidenceFilter: string;
  setConfidenceFilter: (val: string) => void;
  isFilterActive: boolean;
  onResetFilters: () => void;
}

export const FindingsFilterBar: React.FC<FindingsFilterBarProps> = ({
  searchQuery,
  setSearchQuery,
  severityFilter,
  setSeverityFilter,
  verificationFilter,
  setVerificationFilter,
  confidenceFilter,
  setConfidenceFilter,
  isFilterActive,
  onResetFilters,
}) => {
  return (
    <div className="panel" style={{ padding: '0.875rem 1.25rem' }}>
      <div className="row-between responsive-stack">
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
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', paddingLeft: '2.2rem' }}
            aria-label="Search findings by title, asset, and description"
          />
        </div>

        {/* Filters Group */}
        <div className="row" style={{ flexWrap: 'wrap' }}>
          {/* Severity Filter */}
          <div className="row" style={{ gap: '0.25rem' }}>
            <span className="dim text-xs" style={{ fontWeight: 600 }}>
              SEVERITY:
            </span>
            <select
              className="input-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
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
          <div className="row" style={{ gap: '0.25rem' }}>
            <span className="dim text-xs" style={{ fontWeight: 600 }}>
              VERIFICATION:
            </span>
            <select
              className="input-select"
              value={verificationFilter}
              onChange={(e) => setVerificationFilter(e.target.value)}
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
          <div className="row" style={{ gap: '0.25rem' }}>
            <span className="dim text-xs" style={{ fontWeight: 600 }}>
              CONFIDENCE:
            </span>
            <select
              className="input-select"
              value={confidenceFilter}
              onChange={(e) => setConfidenceFilter(e.target.value)}
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
              className="btn btn-secondary btn-xs"
              onClick={onResetFilters}
              title="Reset all search queries and filters"
            >
              <RotateCcw size={12} />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
