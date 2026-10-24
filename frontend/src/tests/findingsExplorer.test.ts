import { describe, it, expect } from 'vitest';
import { DEMO_FINDINGS, DEMO_EVIDENCE, DEMO_AI_ANALYSIS } from '../data/demoData';
import type { Finding, FindingSeverity, ConfidenceLevel } from '../types';

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

// Filter helper mirroring FindingsPage logic
function filterFindings(
  findings: Finding[],
  searchQuery: string,
  severity: string,
  verification: string,
  confidence: string
): Finding[] {
  return findings.filter((f) => {
    if (severity !== 'all' && f.severity !== severity) return false;
    if (verification !== 'all' && f.verification_status !== verification) return false;
    if (confidence !== 'all' && f.confidence !== confidence) return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase().trim();
      const matchesTitle = f.title.toLowerCase().includes(q);
      const matchesAsset = (f.asset_id || '').toLowerCase().includes(q);
      const matchesDesc = f.description.toLowerCase().includes(q);
      const matchesCwe = (f.cwe || '').toLowerCase().includes(q);
      const matchesCve = (f.cve || '').toLowerCase().includes(q);
      if (!matchesTitle && !matchesAsset && !matchesDesc && !matchesCwe && !matchesCve) return false;
    }
    return true;
  });
}

// Sort helper mirroring FindingsPage logic
function sortFindings(
  findings: Finding[],
  sortBy: 'severity' | 'confidence' | 'title',
  order: 'asc' | 'desc'
): Finding[] {
  return [...findings].sort((a, b) => {
    let comparison = 0;
    if (sortBy === 'severity') {
      comparison = SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
    } else if (sortBy === 'confidence') {
      comparison = CONFIDENCE_WEIGHT[a.confidence] - CONFIDENCE_WEIGHT[b.confidence];
    } else if (sortBy === 'title') {
      comparison = a.title.localeCompare(b.title);
    }
    return order === 'desc' ? -comparison : comparison;
  });
}

describe('Findings Explorer Logic', () => {
  const labFindings = DEMO_FINDINGS.filter((f) => f.assessment_id === 'asm_lab_001');

  it('searches by title accurately', () => {
    const results = filterFindings(labFindings, 'SQL Injection', 'all', 'all', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('fnd_001');
  });

  it('searches by affected asset identifier', () => {
    const results = filterFindings(labFindings, 'ast_002', 'all', 'all', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('fnd_004');
    expect(results[0].asset_id).toBe('ast_002');
  });

  it('searches by description text', () => {
    const results = filterFindings(labFindings, 'non-constant-time string comparison', 'all', 'all', 'all');
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('fnd_006');
  });

  it('handles empty search results cleanly', () => {
    const results = filterFindings(labFindings, 'non_existent_exploit_xyz', 'all', 'all', 'all');
    expect(results).toHaveLength(0);
  });

  it('filters by severity correctly', () => {
    const criticals = filterFindings(labFindings, '', 'critical', 'all', 'all');
    expect(criticals.every((f) => f.severity === 'critical')).toBe(true);

    const mediums = filterFindings(labFindings, '', 'medium', 'all', 'all');
    expect(mediums.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('filters by verification status and isolates unverified findings', () => {
    const unverified = filterFindings(labFindings, '', 'all', 'unverified', 'all');
    expect(unverified).toHaveLength(1);
    expect(unverified[0].id).toBe('fnd_006');
    expect(unverified[0].verification_status).toBe('unverified');
    // Unverified finding must not have empirical proof
    expect(unverified[0].evidence_references).toHaveLength(0);

    const falsePositives = filterFindings(labFindings, '', 'all', 'false_positive', 'all');
    expect(falsePositives).toHaveLength(1);
    expect(falsePositives[0].id).toBe('fnd_007');
  });

  it('differentiates confidence from severity', () => {
    // Finding with High Severity but Low Confidence
    const highSevLowConf = filterFindings(labFindings, '', 'high', 'all', 'low');
    expect(highSevLowConf).toHaveLength(1);
    expect(highSevLowConf[0].id).toBe('fnd_007');
    expect(highSevLowConf[0].severity).toBe('high');
    expect(highSevLowConf[0].confidence).toBe('low');
  });

  it('sorts by severity in descending order (critical first)', () => {
    const sorted = sortFindings(labFindings, 'severity', 'desc');
    expect(sorted[0].severity).toBe('critical');
    const weights = sorted.map((f) => SEVERITY_WEIGHT[f.severity]);
    for (let i = 0; i < weights.length - 1; i++) {
      expect(weights[i]).toBeGreaterThanOrEqual(weights[i + 1]);
    }
  });

  it('sorts by confidence in descending order (high first)', () => {
    const sorted = sortFindings(labFindings, 'confidence', 'desc');
    expect(sorted[0].confidence).toBe('high');
    const weights = sorted.map((f) => CONFIDENCE_WEIGHT[f.confidence]);
    for (let i = 0; i < weights.length - 1; i++) {
      expect(weights[i]).toBeGreaterThanOrEqual(weights[i + 1]);
    }
  });

  it('validates evidence provenance and absence handling in detail view', () => {
    // 1. Finding with evidence
    const sqli = labFindings.find((f) => f.id === 'fnd_001')!;
    const sqliEvidence = DEMO_EVIDENCE.filter((e) => sqli.evidence_references.includes(e.id));
    expect(sqliEvidence).toHaveLength(1);
    expect(sqliEvidence[0].id).toBe('ev_sql_001');

    // 2. Finding with absent evidence
    const timing = labFindings.find((f) => f.id === 'fnd_006')!;
    const timingEvidence = DEMO_EVIDENCE.filter((e) => timing.evidence_references.includes(e.id));
    expect(timingEvidence).toHaveLength(0);

    // 3. AI analysis exists but explicitly acknowledges evidence absence
    const timingAI = DEMO_AI_ANALYSIS['fnd_006'];
    expect(timingAI).toBeDefined();
    expect(timingAI.cited_evidence_ids).toHaveLength(0);
    expect(timingAI.limitations_and_missing_evidence.some((m) => m.includes('EVIDENCE GAP'))).toBe(true);
  });
});
