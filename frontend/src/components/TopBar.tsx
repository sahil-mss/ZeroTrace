import React from 'react';
import { useApp } from '../context/AppContext';
import {
  Sun,
  Moon,
  Search,
  Shield,
  Square,
  Play,
  Terminal,
} from 'lucide-react';
import { AssessmentStatusBadge } from './Badge';

export const TopBar: React.FC = () => {
  const {
    theme,
    toggleTheme,
    assessments,
    currentAssessmentId,
    setCurrentAssessmentId,
    currentAssessment,
    globalSearch,
    setGlobalSearch,
    startAssessment,
    cancelAssessment,
  } = useApp();

  return (
    <header
      style={{
        height: '56px',
        backgroundColor: 'var(--color-surface)',
        borderBottom: '1px solid var(--color-border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 1.5rem',
        gap: '1rem',
      }}
    >
      {/* Left: Assessment Selector & Active Target */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-text-dim)' }}>
          <Shield size={16} />
          <span style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>Scope:</span>
        </div>

        <select
          value={currentAssessmentId}
          onChange={(e) => setCurrentAssessmentId(e.target.value)}
          className="input-select"
          style={{ fontWeight: 600, paddingRight: '1.75rem' }}
          aria-label="Select active assessment"
        >
          {assessments.map((asm) => (
            <option key={asm.id} value={asm.id}>
              {asm.name} ({asm.target})
            </option>
          ))}
        </select>

        {currentAssessment && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span
              className="font-mono"
              style={{
                fontSize: '0.75rem',
                backgroundColor: 'var(--color-surface-subtle)',
                padding: '0.2rem 0.5rem',
                borderRadius: '3px',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-muted)',
              }}
            >
              {currentAssessment.target}
            </span>
            <AssessmentStatusBadge status={currentAssessment.status} />
          </div>
        )}
      </div>

      {/* Center: Global Search */}
      <div style={{ flex: 1, maxWidth: '420px', position: 'relative' }}>
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
          placeholder="Filter findings, assets, CWEs, CVEs..."
          value={globalSearch}
          onChange={(e) => setGlobalSearch(e.target.value)}
          style={{
            width: '100%',
            paddingLeft: '2.2rem',
          }}
          aria-label="Global search filter"
        />
        {globalSearch && (
          <button
            onClick={() => setGlobalSearch('')}
            style={{
              position: 'absolute',
              right: '0.5rem',
              top: '50%',
              transform: 'translateY(-50%)',
              fontSize: '0.7rem',
              color: 'var(--color-text-dim)',
              padding: '0.2rem',
            }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Right: Actions, Theme Switcher & Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {currentAssessment?.status === 'in_progress' ? (
          <button
            className="btn btn-danger"
            onClick={() => cancelAssessment(currentAssessment.id)}
            title="Immediately halt all background scan workers"
          >
            <Square size={13} fill="currentColor" />
            <span>Emergency Stop</span>
          </button>
        ) : currentAssessment?.status === 'pending' ? (
          <button
            className="btn btn-primary"
            onClick={() => startAssessment(currentAssessment.id)}
          >
            <Play size={13} fill="currentColor" />
            <span>Start Assessment</span>
          </button>
        ) : null}

        {/* Engine mode tag */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            fontSize: '0.72rem',
            color: 'var(--color-text-muted)',
            backgroundColor: 'var(--color-surface-subtle)',
            padding: '0.3rem 0.6rem',
            borderRadius: '4px',
            border: '1px solid var(--color-border)',
          }}
        >
          <Terminal size={12} />
          <span style={{ fontWeight: 600 }}>API v1.0</span>
        </div>

        {/* Theme Toggle */}
        <button
          className="btn btn-icon"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label="Toggle visual theme"
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
      </div>
    </header>
  );
};
