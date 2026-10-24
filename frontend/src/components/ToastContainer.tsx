import React from 'react';
import { useApp } from '../context/AppContext';
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useApp();

  if (toasts.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        bottom: '1.5rem',
        right: '1.5rem',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
        maxWidth: '400px',
        width: 'calc(100% - 3rem)',
      }}
    >
      {toasts.map((toast) => {
        let borderColor = 'var(--color-border)';
        let IconComponent = Info;
        let iconColor = 'var(--color-text-muted)';

        if (toast.type === 'success') {
          borderColor = 'var(--color-ver-confirmed-border)';
          IconComponent = CheckCircle2;
          iconColor = 'var(--color-ver-confirmed-text)';
        } else if (toast.type === 'warning') {
          borderColor = 'var(--color-sev-medium-border)';
          IconComponent = AlertTriangle;
          iconColor = 'var(--color-sev-medium-text)';
        } else if (toast.type === 'error') {
          borderColor = 'var(--color-sev-critical-border)';
          IconComponent = AlertCircle;
          iconColor = 'var(--color-sev-critical-text)';
        }

        return (
          <div
            key={toast.id}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.75rem',
              padding: '0.875rem 1rem',
              backgroundColor: 'var(--color-surface)',
              border: `1px solid ${borderColor}`,
              borderRadius: '4px',
              boxShadow: 'var(--shadow-md)',
            }}
          >
            <IconComponent size={18} style={{ color: iconColor, marginTop: '2px', flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text-main)' }}>
                {toast.title}
              </div>
              {toast.message && (
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                  {toast.message}
                </div>
              )}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--color-text-dim)',
                cursor: 'pointer',
                padding: '2px',
                lineHeight: 1,
              }}
              aria-label="Dismiss toast"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
};
