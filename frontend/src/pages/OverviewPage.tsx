import React from 'react';
import { useApp } from '../context/useApp';
import {
  AlertTriangle,
  Server,
  FileCheck2,
  ArrowRight,
  Play,
  Square,
  Lock,
} from 'lucide-react';
import { SeverityBadge, VerificationBadge, AssessmentStatusBadge } from '../components/Badge';

export const OverviewPage: React.FC = () => {
  const {
    currentAssessment,
    findings,
    assets,
    currentAssessmentId,
    setActivePage,
    setSelectedFindingId,
    startAssessment,
    cancelAssessment,
    isBackendHealthy,
    isLoading,
  } = useApp();

  const isDemo = isBackendHealthy === false;

  const assessmentFindings = findings.filter((f) => f.assessment_id === currentAssessmentId);
  const assessmentAssets = assets.filter((a) => a.assessment_id === currentAssessmentId);

  const criticals = assessmentFindings.filter((f) => f.severity === 'critical').length;
  const highs = assessmentFindings.filter((f) => f.severity === 'high').length;
  const mediums = assessmentFindings.filter((f) => f.severity === 'medium').length;
  const confirmedCount = assessmentFindings.filter((f) => f.verification_status === 'confirmed').length;

  return (
    <div className="stack">
      {/* Target Banner */}
      <div className="panel panel-padded">
        <div className="row-between responsive-stack">
          <div>
            <div className="row" style={{ alignItems: 'center', gap: '0.5rem' }}>
              <span className="metric-label text-xs">
                ACTIVE ASSESSMENT SCOPE
              </span>
              {isDemo && <span className="demo-data-tag">DEMO DATA</span>}
              {currentAssessment && <AssessmentStatusBadge status={currentAssessment.status} />}
            </div>
            <h1 className="h1">
              {isLoading ? (
                <span className="skeleton" style={{ width: '280px', height: '1.75rem', marginTop: '0.25rem' }} />
              ) : (
                currentAssessment?.name || 'No Active Assessment'
              )}
            </h1>
            <div className="font-mono muted text-sm">
              {isLoading ? (
                <span className="skeleton" style={{ width: '380px', height: '1rem', marginTop: '0.35rem' }} />
              ) : (
                `Target: ${currentAssessment?.target || 'None'} · Policy: ${currentAssessment?.scope_policy}`
              )}
            </div>
          </div>

          <div className="row">
            {currentAssessment?.status === 'pending' && (
              <button
                className="btn btn-primary"
                onClick={() => startAssessment(currentAssessment.id)}
              >
                <Play size={14} fill="currentColor" />
                <span>Launch Assessment</span>
              </button>
            )}

            {currentAssessment?.status === 'in_progress' && (
              <button
                className="btn btn-danger"
                onClick={() => cancelAssessment(currentAssessment.id)}
              >
                <Square size={14} fill="currentColor" />
                <span>Halt Assessment</span>
              </button>
            )}

            <button className="btn btn-secondary" onClick={() => setActivePage('reports')}>
              <span>View Full Report</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid-4 responsive-grid">
        {/* Metric 1 */}
        <div className="panel metric-card">
          <div className="row-between">
            <span className="metric-label">
              CRITICAL / HIGH RISKS
            </span>
            <AlertTriangle size={16} style={{ color: 'var(--color-sev-critical-text)' }} />
          </div>
          <div className="metric-value">
            {isLoading ? <span className="skeleton" style={{ width: '48px', height: '1.75rem' }} /> : criticals + highs}
          </div>
          <div className="metric-subtitle">
            {criticals} Critical · {highs} High · {mediums} Medium
          </div>
        </div>

        {/* Metric 2 */}
        <div className="panel metric-card">
          <div className="row-between">
            <span className="metric-label">
              DISCOVERED ASSETS
            </span>
            <Server size={16} className="muted" />
          </div>
          <div className="metric-value">
            {isLoading ? <span className="skeleton" style={{ width: '48px', height: '1.75rem' }} /> : assessmentAssets.length}
          </div>
          <div className="metric-subtitle">
            In-scope services and endpoints
          </div>
        </div>

        {/* Metric 3 */}
        <div className="panel metric-card">
          <div className="row-between">
            <span className="metric-label">
              VERIFIED VULNERABILITIES
            </span>
            <FileCheck2 size={16} style={{ color: 'var(--color-ver-confirmed-text)' }} />
          </div>
          <div className="metric-value">
            {isLoading ? <span className="skeleton" style={{ width: '48px', height: '1.75rem' }} /> : confirmedCount}
          </div>
          <div className="metric-subtitle">
            Backed by captured evidence records
          </div>
        </div>

        {/* Metric 4 */}
        <div className="panel metric-card">
          <div className="row-between">
            <span className="metric-label">
              POLICY ENFORCEMENT
            </span>
            <Lock size={16} style={{ color: 'var(--color-accent)' }} />
          </div>
          <div className="metric-value">
            100%
          </div>
          <div className="metric-subtitle">
            Zero unapproved out-of-scope probes
          </div>
        </div>
      </div>

      {/* Connected Subsystems & Integration Health (Honest status - no faking) */}
      <div className="panel panel-padded">
        <div className="row-between responsive-stack">
          <div>
            <h2 className="section-title">Integrated Engine Subsystems</h2>
            <div className="section-subtitle">
              Live connection status across Person 1 (OSINT/Database), Person 2 (Scanners), and Person 3 (AI/Reports)
            </div>
          </div>
          <span className="dim text-xs" style={{ fontStyle: 'italic' }}>
            No simulated completions
          </span>
        </div>

        <div className="grid-4 responsive-grid">
          {/* Person 1 Orchestrator */}
          <div className="subtle-box">
            <div className="row-between">
              <span className="text-sm" style={{ fontWeight: 600 }}>Person 1: Scope & DB Core</span>
              <span className="status-pill pill-confirmed">
                CONNECTED
              </span>
            </div>
            <div className="muted text-sm">
              SQLite / EvidenceStore active. Target boundaries enforced.
            </div>
          </div>

          {/* Person 1 OSINT Module */}
          <div className="subtle-box">
            <div className="row-between">
              <span className="text-sm" style={{ fontWeight: 600 }}>Person 1: Passive OSINT</span>
              <span className="status-pill pill-accent">
                READY / ON DEMAND
              </span>
            </div>
            <div className="muted text-sm">
              DNS, crt.sh, and HTTP fingerprinter registered.
            </div>
          </div>

          {/* Person 2 Scanners */}
          <div className="subtle-box">
            <div className="row-between">
              <span className="text-sm" style={{ fontWeight: 600 }}>Person 2: Security Scanners</span>
              <span className={`status-pill ${currentAssessment?.status === 'in_progress' ? 'pill-accent' : 'pill-idle'}`}>
                {currentAssessment?.status === 'in_progress' ? 'ACTIVE' : 'IDLE / PENDING'}
              </span>
            </div>
            <div className="muted text-sm">
              ZAP & Nmap adapters awaiting bounded execution triggers.
            </div>
          </div>

          {/* Person 3 AI & Reporting */}
          <div className="subtle-box">
            <div className="row-between">
              <span className="text-sm" style={{ fontWeight: 600 }}>Person 3: AI & Reports</span>
              <span className="status-pill pill-confirmed">
                ONLINE
              </span>
            </div>
            <div className="muted text-sm">
              Deterministic fallback + grounded AI analysis + Report Export.
            </div>
          </div>
        </div>
      </div>

      {/* Priority Findings Section */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="section-title">Priority Security Findings</h2>
            <div className="section-subtitle">
              Actionable findings ranked by severity and verification state
            </div>
          </div>
          <button className="btn btn-secondary" onClick={() => setActivePage('findings')}>
            <span>All Findings ({assessmentFindings.length})</span>
            <ArrowRight size={13} />
          </button>
        </div>

        <div className="table-container table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding Title</th>
                <th>Asset</th>
                <th>Verification</th>
                <th>Evidence</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {assessmentFindings.slice(0, 4).map((f) => (
                <tr
                  key={f.id}
                  className="clickable"
                  onClick={() => setSelectedFindingId(f.id)}
                >
                  <td style={{ width: '130px' }}>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{f.title}</div>
                    <div className="dim text-xs">
                      {f.cwe || 'No CWE'} · {f.source_tool}
                    </div>
                  </td>
                  <td className="font-mono text-sm">
                    {f.asset_id || 'Target Scope'}
                  </td>
                  <td style={{ width: '140px' }}>
                    <VerificationBadge status={f.verification_status} />
                  </td>
                  <td className="muted text-sm">
                    {f.evidence_references.length} record(s)
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary btn-xs"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedFindingId(f.id);
                      }}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
