import React, { useState } from 'react';
import { useApp } from '../context/useApp';
import {
  Sun,
  Moon,
  Search,
  Shield,
  Square,
  Play,
  Terminal,
  Menu,
  Key,
  X,
  Check,
} from 'lucide-react';
import { AssessmentStatusBadge } from './Badge';
import { apiClient } from '../api/client';

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
    sidebarOpen,
    setSidebarOpen,
    addToast,
  } = useApp();

  const [showTokenModal, setShowTokenModal] = useState(false);
  const [tokenInput, setTokenInput] = useState(() => apiClient.getAuthToken());

  const handleSaveToken = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = tokenInput.trim();
    apiClient.setConfig({ authToken: trimmed });
    setShowTokenModal(false);
    addToast(
      'API Authentication Updated',
      trimmed
        ? 'API Bearer token updated and saved in session storage.'
        : 'API Bearer token removed.',
      'info'
    );
  };

  return (
    <header className="topbar">
      {/* Left: Hamburger & Assessment Selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <button
          className="btn btn-icon sidebar-toggle"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-label={sidebarOpen ? 'Close navigation sidebar' : 'Open navigation sidebar'}
          aria-expanded={sidebarOpen}
        >
          <Menu size={18} />
        </button>

        <div className="scope-indicator" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-text-dim)' }}>
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

        {/* API Token Settings Button */}
        <button
          className="btn btn-icon"
          onClick={() => {
            setTokenInput(apiClient.getAuthToken());
            setShowTokenModal(true);
          }}
          title="Configure API Bearer Token"
          aria-label="Configure API Bearer Token"
          style={{ position: 'relative' }}
        >
          <Key size={16} />
          {apiClient.getAuthToken() && (
            <span
              style={{
                position: 'absolute',
                top: '4px',
                right: '4px',
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: 'var(--color-accent)',
              }}
            />
          )}
        </button>

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

      {/* API Token Configuration Modal */}
      {showTokenModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="token-modal-title"
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1rem',
          }}
          onClick={() => setShowTokenModal(false)}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: '460px',
              backgroundColor: 'var(--color-surface)',
              border: '1px solid var(--color-border-strong)',
              boxShadow: 'var(--shadow-md)',
              padding: '1.5rem',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Key size={18} style={{ color: 'var(--color-accent)' }} />
                <h3 id="token-modal-title" style={{ fontSize: '1rem', margin: 0 }}>
                  API Authentication Token
                </h3>
              </div>
              <button
                className="btn btn-icon"
                onClick={() => setShowTokenModal(false)}
                aria-label="Close API token settings"
              >
                <X size={16} />
              </button>
            </div>

            <p style={{ fontSize: '0.8rem', color: 'var(--color-text-dim)', marginBottom: '1.25rem', lineHeight: 1.5 }}>
              Set your API Bearer token for authenticating with the ZeroTrace backend. This token is saved in your browser's session storage and sent in the <code style={{ color: 'var(--color-text-main)', background: 'var(--color-surface-subtle)', padding: '0.1rem 0.3rem', borderRadius: '3px' }}>Authorization: Bearer</code> header.
            </p>

            <form onSubmit={handleSaveToken}>
              <div style={{ marginBottom: '1.25rem' }}>
                <label
                  htmlFor="api-token-input"
                  style={{
                    display: 'block',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    color: 'var(--color-text-muted)',
                    marginBottom: '0.4rem',
                  }}
                >
                  Bearer Token
                </label>
                <input
                  id="api-token-input"
                  type="password"
                  className="input-text"
                  placeholder="Paste Bearer token (e.g. secret token)"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}
                  autoFocus
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowTokenModal(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  <Check size={14} />
                  <span>Save Token</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </header>
  );
};
