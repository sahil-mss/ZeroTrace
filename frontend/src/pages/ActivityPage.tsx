import React, { useState } from 'react';
import { useApp } from '../context/useApp';
import { CheckCircle2, AlertTriangle, AlertCircle, Info } from 'lucide-react';

export const ActivityPage: React.FC = () => {
  const { activityLogs, currentAssessmentId, globalSearch } = useApp();
  const [componentFilter, setComponentFilter] = useState<string>('all');
  const [levelFilter, setLevelFilter] = useState<string>('all');

  const currentLogs = activityLogs.filter(
    (log) => !log.assessment_id || log.assessment_id === currentAssessmentId
  );

  const filteredLogs = currentLogs.filter((log) => {
    if (componentFilter !== 'all' && log.component !== componentFilter) return false;
    if (levelFilter !== 'all' && log.level !== levelFilter) return false;

    if (globalSearch) {
      const q = globalSearch.toLowerCase();
      return (
        log.message.toLowerCase().includes(q) ||
        log.component.toLowerCase().includes(q) ||
        (log.details && log.details.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="h1">Assessment Activity & Audit Logs</h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Tamper-evident system activity, tool executions, and scope enforcement decisions.
          </p>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <select
            className="input-select"
            value={componentFilter}
            onChange={(e) => setComponentFilter(e.target.value)}
            aria-label="Filter by component"
          >
            <option value="all">All Subsystems</option>
            <option value="SCOPE_ENGINE">Scope Engine</option>
            <option value="OSINT_ADAPTER">OSINT Adapter</option>
            <option value="SCANNER_WORKER">Scanner Worker</option>
            <option value="AI_REASONER">AI Reasoner</option>
          </select>

          <select
            className="input-select"
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            aria-label="Filter by log level"
          >
            <option value="all">All Log Levels</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="success">Success</option>
          </select>
        </div>
      </div>

      {/* Logs Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '170px' }}>Timestamp (UTC)</th>
              <th style={{ width: '100px' }}>Level</th>
              <th style={{ width: '160px' }}>Component</th>
              <th>Audit Log Message</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', padding: '3rem', color: 'var(--color-text-dim)' }}>
                  No activity log entries match the selected filters.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                let levelBadge = (
                  <span className="badge badge-informational">
                    <Info size={11} /> INFO
                  </span>
                );
                if (log.level === 'warning') {
                  levelBadge = (
                    <span className="badge badge-medium">
                      <AlertTriangle size={11} /> WARN
                    </span>
                  );
                } else if (log.level === 'error') {
                  levelBadge = (
                    <span className="badge badge-critical">
                      <AlertCircle size={11} /> ERROR
                    </span>
                  );
                } else if (log.level === 'success') {
                  levelBadge = (
                    <span className="badge badge-confirmed">
                      <CheckCircle2 size={11} /> OK
                    </span>
                  );
                }

                return (
                  <tr key={log.id}>
                    <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
                      {new Date(log.timestamp).toLocaleTimeString()} · {new Date(log.timestamp).toLocaleDateString()}
                    </td>
                    <td>{levelBadge}</td>
                    <td>
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '0.72rem',
                          backgroundColor: 'var(--color-surface-subtle)',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '3px',
                          border: '1px solid var(--color-border)',
                          fontWeight: 600,
                        }}
                      >
                        {log.component}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--color-text-main)' }}>
                      {log.message}
                      {log.details && (
                        <div
                          className="font-mono"
                          style={{
                            fontSize: '0.72rem',
                            color: 'var(--color-text-dim)',
                            marginTop: '2px',
                          }}
                        >
                          {log.details}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
