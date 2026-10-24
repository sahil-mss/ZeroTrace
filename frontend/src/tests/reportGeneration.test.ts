import { describe, it, expect } from 'vitest';
import {
  compileAssessmentReport,
  generateReportMarkdown,
  escapeHtml,
} from '../services/reportExport';
import {
  DEMO_ASSESSMENTS,
  DEMO_ASSETS,
  DEMO_FINDINGS,
  DEMO_EVIDENCE,
  DEMO_AI_ANALYSIS,
} from '../data/demoData';
import type { Assessment, Asset, Finding } from '../types';

describe('Assessment Report Generation & Export Service', () => {
  it('1. Compiles complete report from stored data with mixed severities and verification statuses', () => {
    const assessment = DEMO_ASSESSMENTS.find((a) => a.id === 'asm_lab_001')!;
    const report = compileAssessmentReport(
      assessment,
      DEMO_ASSETS,
      DEMO_FINDINGS,
      DEMO_EVIDENCE,
      DEMO_AI_ANALYSIS
    );

    expect(report).not.toBeNull();
    if (!report) return;

    // 1. Assessment metadata
    expect(report.assessment.id).toBe('asm_lab_001');
    expect(report.assessment.target).toBe('http://127.0.0.1:3000');
    expect(report.assessment.scope_policy).toBe('STRICT_SINGLE_HOST');

    // 2. Executive summary
    expect(report.executive_summary).toContain('OWASP Juice Shop (Lab Assessment)');
    expect(report.executive_summary).toContain('STRICT_SINGLE_HOST');

    // 3. Scope and methodology
    expect(report.scope_and_methodology.policy).toBe('STRICT_SINGLE_HOST');
    expect(report.scope_and_methodology.observed_services_count).toBeGreaterThan(0);
    expect(report.scope_and_methodology.recorded_evidence_count).toBeGreaterThan(0);

    // 4. Asset inventory summary (ast_001, ast_002, ast_003, ast_004 for asm_lab_001)
    expect(report.asset_inventory.total).toBe(4);
    expect(report.asset_inventory.items.some((a) => a.hostname_or_address.includes('127.0.0.1'))).toBe(true);

    // 5. Findings summary grouped by severity and verification
    expect(report.findings_summary.total).toBe(6);
    expect(report.findings_summary.by_severity.critical).toBe(1);
    expect(report.findings_summary.by_severity.high).toBe(2);
    expect(report.findings_summary.by_severity.medium).toBe(1);
    expect(report.findings_summary.by_severity.low).toBe(1);
    expect(report.findings_summary.by_severity.informational).toBe(1);

    // Mixed verification status distinction
    expect(report.findings_summary.by_verification.confirmed).toBe(3);
    expect(report.findings_summary.by_verification.likely).toBe(1);
    expect(report.findings_summary.by_verification.unverified).toBe(1);
    expect(report.findings_summary.by_verification.false_positive).toBe(1);

    // 6. Individual finding details
    const sqli = report.finding_details.find((f) => f.id === 'fnd_001');
    expect(sqli).toBeDefined();
    expect(sqli?.severity).toBe('critical');
    expect(sqli?.verification_status).toBe('confirmed');
    expect(sqli?.evidence_references).toContain('ev_sql_001');
    expect(sqli?.ai_interpretation).toBeDefined();
    expect(sqli?.ai_interpretation?.summary).toContain('SQL injection');

    // 7. Limitations, missing evidence, and unverified findings
    expect(report.limitations_and_gaps.unverified_findings_count).toBe(1);
    expect(report.limitations_and_gaps.findings_without_evidence_count).toBe(1);
    const unverifiedLimitation = report.limitations_and_gaps.documented_items.find(
      (item) => item.finding_id === 'fnd_006'
    );
    expect(unverifiedLimitation).toBeDefined();
    expect(unverifiedLimitation?.reason).toContain('UNVERIFIED');

    // 8. Prioritized remediation checklist (false positives excluded)
    expect(report.remediation_checklist.length).toBe(5);
    expect(report.remediation_checklist[0].finding_id).toBe('fnd_001'); // Critical is #1
    expect(report.remediation_checklist.every((c) => c.verification_status !== 'false_positive')).toBe(true);
  });

  it('2. Properly handles empty-data state without hallucinating statistics or throwing errors', () => {
    const emptyAssessment: Assessment = {
      id: 'asm_empty_099',
      name: 'Clean Slate Test Sandbox',
      target: 'http://192.168.1.50',
      status: 'pending',
      created_at: '2026-10-24T20:00:00Z',
      scope_policy: 'EMPTY_SANDBOX_CONSTRAINED',
      allowed_checks: ['passive_recon'],
    };

    const emptyAssets: Asset[] = [];
    const emptyFindings: Finding[] = [];

    const report = compileAssessmentReport(
      emptyAssessment,
      emptyAssets,
      emptyFindings,
      [],
      {}
    );

    expect(report).not.toBeNull();
    if (!report) return;

    expect(report.assessment.id).toBe('asm_empty_099');
    expect(report.asset_inventory.total).toBe(0);
    expect(report.findings_summary.total).toBe(0);
    expect(report.findings_summary.by_severity.critical).toBe(0);
    expect(report.findings_summary.by_verification.confirmed).toBe(0);
    expect(report.finding_details).toHaveLength(0);
    expect(report.limitations_and_gaps.documented_items).toHaveLength(0);
    expect(report.remediation_checklist).toHaveLength(0);
    expect(report.executive_summary).toContain('zero vulnerability records');

    // Markdown generation handles empty states gracefully
    const md = generateReportMarkdown(report);
    expect(md).toContain('No asset inventory records logged');
    expect(md).toContain('No findings recorded for this assessment');
    expect(md).toContain('No actionable remediation items required');
  });

  it('3. Generates grounded Markdown export with distinct sections and evidence citations', () => {
    const assessment = DEMO_ASSESSMENTS.find((a) => a.id === 'asm_lab_001')!;
    const report = compileAssessmentReport(
      assessment,
      DEMO_ASSETS,
      DEMO_FINDINGS,
      DEMO_EVIDENCE,
      DEMO_AI_ANALYSIS
    )!;

    const md = generateReportMarkdown(report);

    expect(md).toContain('# Security Assessment Report: OWASP Juice Shop (Lab Assessment)');
    expect(md).toContain('## 1. Executive Summary');
    expect(md).toContain('## 2. Scope & Methodology');
    expect(md).toContain('## 3. Asset Inventory');
    expect(md).toContain('## 4. Findings Summary');
    expect(md).toContain('## 5. Detailed Technical Findings');
    expect(md).toContain('## 6. Limitations, Missing Evidence & Unverified Findings');
    expect(md).toContain('## 7. Prioritized Remediation Checklist');

    // Confirms evidence citations exist
    expect(md).toContain('`ev_sql_001`');
    // Confirms AI label is clear
    expect(md).toContain('AI Interpretation');
  });

  it('4. Correctly isolates assessment data when switching assessments', () => {
    const dvwaAssessment = DEMO_ASSESSMENTS.find((a) => a.id === 'asm_lab_002')!;
    const dvwaReport = compileAssessmentReport(
      dvwaAssessment,
      DEMO_ASSETS,
      DEMO_FINDINGS,
      DEMO_EVIDENCE,
      DEMO_AI_ANALYSIS
    )!;

    expect(dvwaReport.assessment.id).toBe('asm_lab_002');
    expect(dvwaReport.assessment.target).toBe('http://10.0.4.15:8080');
    // Only fnd_005 belongs to asm_lab_002
    expect(dvwaReport.findings_summary.total).toBe(1);
    expect(dvwaReport.finding_details[0].id).toBe('fnd_005');
  });

  it('5. Escapes untrusted text before HTML rendering', () => {
    const rawMalicious = '<script>alert("xss")</script>&"\'';
    const escaped = escapeHtml(rawMalicious);
    expect(escaped).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;&amp;&quot;&#039;');
    expect(escaped).not.toContain('<script>');
  });
});
