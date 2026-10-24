import React, { useState } from 'react';
import { useApp } from '../context/useApp';
import {
  Play,
  Square,
  Lock,
  Plus,
  X,
} from 'lucide-react';
import { AssessmentStatusBadge } from '../components/Badge';

export const AssessmentsPage: React.FC = () => {
  const {
    assessments,
    currentAssessmentId,
    setCurrentAssessmentId,
    startAssessment,
    cancelAssessment,
    createNewAssessment,
    addToast,
  } = useApp();

  const [showModal, setShowModal] = useState(false);
  const [newName, setNewName] = useState('');
  const [newTarget, setNewTarget] = useState('');
  const [newPolicy, setNewPolicy] = useState('STRICT_SINGLE_HOST');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newTarget.trim()) {
      addToast('Validation Error', 'Assessment name and target URL/host are required.', 'error');
      return;
    }
    createNewAssessment(newName, newTarget, newPolicy);
    setShowModal(false);
    setNewName('');
    setNewTarget('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 className="h1">Authorized Assessments</h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Enforce approved targets, permission boundaries, and audit controls.
          </p>
        </div>

        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={14} />
          <span>Authorize New Target</span>
        </button>
      </div>

      {/* Table of Assessments */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Assessment Name</th>
              <th>Target Host</th>
              <th>Scope Policy</th>
              <th>Status</th>
              <th>Allowed Checks</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {assessments.map((asm) => {
              const isSelected = asm.id === currentAssessmentId;
              return (
                <tr
                  key={asm.id}
                  className={isSelected ? 'selected' : ''}
                  style={{
                    backgroundColor: isSelected ? 'var(--color-surface-hover)' : 'inherit',
                  }}
                >
                  <td className="font-mono" style={{ fontSize: '0.78rem', width: '130px' }}>
                    {asm.id}
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--color-text-main)' }}>{asm.name}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--color-text-dim)' }}>
                      Created: {new Date(asm.created_at).toLocaleString()}
                    </div>
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.8125rem' }}>
                    {asm.target}
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Lock size={12} style={{ color: 'var(--color-accent)' }} />
                      <span>{asm.scope_policy}</span>
                    </div>
                  </td>
                  <td style={{ width: '130px' }}>
                    <AssessmentStatusBadge status={asm.status} />
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    {asm.allowed_checks.join(', ')}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                      {!isSelected && (
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.72rem' }}
                          onClick={() => setCurrentAssessmentId(asm.id)}
                        >
                          Select
                        </button>
                      )}

                      {asm.status === 'pending' && (
                        <button
                          className="btn btn-primary"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.72rem' }}
                          onClick={() => startAssessment(asm.id)}
                        >
                          <Play size={11} fill="currentColor" /> Start
                        </button>
                      )}

                      {asm.status === 'in_progress' && (
                        <button
                          className="btn btn-danger"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.72rem' }}
                          onClick={() => cancelAssessment(asm.id)}
                        >
                          <Square size={11} fill="currentColor" /> Halt
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Creation Modal */}
      {showModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.65)',
            zIndex: 9990,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.5rem',
          }}
          onClick={() => setShowModal(false)}
        >
          <div
            className="panel"
            style={{ width: '480px', maxWidth: '100%', padding: '1.5rem' }}
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
              <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Authorize Lab Assessment Target</h2>
              <button className="btn-icon" onClick={() => setShowModal(false)}>
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.3rem' }}>
                  ASSESSMENT NAME
                </label>
                <input
                  type="text"
                  className="input-text"
                  placeholder="e.g. Local Payment Gateway Audit"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  style={{ width: '100%' }}
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.3rem' }}>
                  TARGET HOST / URL (AUTHORIZED LAB SCOPE)
                </label>
                <input
                  type="text"
                  className="input-text font-mono"
                  placeholder="e.g. http://127.0.0.1:8080 or lab.internal.test"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  style={{ width: '100%' }}
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.3rem' }}>
                  SCOPE RESTRICTION POLICY
                </label>
                <select
                  className="input-select"
                  value={newPolicy}
                  onChange={(e) => setNewPolicy(e.target.value)}
                  style={{ width: '100%' }}
                >
                  <option value="STRICT_SINGLE_HOST">STRICT_SINGLE_HOST (Exact Hostname Only)</option>
                  <option value="LAB_SUBNET_CONSTRAINED">LAB_SUBNET_CONSTRAINED (RFC1918 Lab Subnet)</option>
                  <option value="EXPLICIT_HOST_ALLOWLIST">EXPLICIT_HOST_ALLOWLIST (Pre-approved list)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Save & Authorize Target
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
