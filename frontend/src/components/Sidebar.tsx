import React from 'react';
import { useApp } from '../context/AppContext';
import type { NavPage } from '../context/AppContext';
import {
  LayoutDashboard,
  ShieldAlert,
  Server,
  AlertTriangle,
  BrainCircuit,
  FileText,
  Activity,
  Lock,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { activePage, setActivePage, findings, currentAssessmentId } = useApp();

  const assessmentFindings = findings.filter((f) => f.assessment_id === currentAssessmentId);
  const criticalCount = assessmentFindings.filter(
    (f) => f.severity === 'critical' || f.severity === 'high'
  ).length;

  const navItems: { id: NavPage; label: string; icon: React.FC<{ size?: number }> }[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'assessments', label: 'Assessments', icon: ShieldAlert },
    { id: 'assets', label: 'Assets', icon: Server },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'ai-analysis', label: 'AI Intelligence', icon: BrainCircuit },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'activity', label: 'Activity Logs', icon: Activity },
  ];

  return (
    <aside
      style={{
        width: '240px',
        backgroundColor: 'var(--color-surface)',
        borderRight: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '1.25rem 1.25rem 1rem 1.25rem',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div
            style={{
              width: '26px',
              height: '26px',
              backgroundColor: 'var(--color-accent)',
              borderRadius: '3px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--color-accent-contrast)',
              fontWeight: 700,
              fontSize: '0.8rem',
              letterSpacing: '-0.02em',
            }}
          >
            ZT
          </div>
          <div>
            <div
              style={{
                fontSize: '0.925rem',
                fontWeight: 700,
                letterSpacing: '0.04em',
                lineHeight: 1.1,
                color: 'var(--color-text-main)',
              }}
            >
              ZEROTRACE
            </div>
            <div
              style={{
                fontSize: '0.68rem',
                color: 'var(--color-text-dim)',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                fontWeight: 600,
              }}
            >
              AegisPT Security Core
            </div>
          </div>
        </div>
      </div>

      {/* Nav List */}
      <nav style={{ padding: '0.75rem', flex: 1, display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
        {navItems.map((item) => {
          const isActive = activePage === item.id;
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => setActivePage(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.55rem 0.75rem',
                borderRadius: '4px',
                fontSize: '0.8125rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--color-text-main)' : 'var(--color-text-muted)',
                backgroundColor: isActive ? 'var(--color-surface-hover)' : 'transparent',
                borderLeft: isActive ? '3px solid var(--color-accent)' : '3px solid transparent',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.12s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <Icon size={16} />
                <span>{item.label}</span>
              </div>
              {item.id === 'findings' && criticalCount > 0 && (
                <span
                  style={{
                    backgroundColor: 'var(--color-sev-critical-bg)',
                    color: 'var(--color-sev-critical-text)',
                    border: '1px solid var(--color-sev-critical-border)',
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    padding: '0.1rem 0.4rem',
                    borderRadius: '10px',
                  }}
                >
                  {criticalCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Policy Engine Badge */}
      <div
        style={{
          padding: '0.875rem 1rem',
          borderTop: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-surface-subtle)',
          fontSize: '0.72rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-text-muted)' }}>
          <Lock size={12} style={{ color: 'var(--color-ver-confirmed-text)' }} />
          <span style={{ fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Policy Engine: Active
          </span>
        </div>
        <div style={{ color: 'var(--color-text-dim)', marginTop: '0.25rem', fontSize: '0.68rem' }}>
          Bounded Lab Sandbox · Strict Scope
        </div>
      </div>
    </aside>
  );
};
