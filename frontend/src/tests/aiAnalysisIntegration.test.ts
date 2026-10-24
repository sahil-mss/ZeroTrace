import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { apiClient } from '../api/client';
import { DEMO_FINDINGS, DEMO_EVIDENCE } from '../data/demoData';
import type { Finding, Evidence } from '../types';

describe('AI Analysis Service & Client Interaction', () => {
  const originalFetch = globalThis.fetch;
  const sqliFinding: Finding = DEMO_FINDINGS.find((f) => f.id === 'fnd_001')!;
  const sqliEvidence: Evidence[] = DEMO_EVIDENCE.filter((e) =>
    sqliFinding.evidence_references.includes(e.id)
  );

  const unverifiedFinding: Finding = DEMO_FINDINGS.find((f) => f.id === 'fnd_006')!;
  const emptyEvidence: Evidence[] = [];

  beforeEach(() => {
    // Force direct client mode (disable dev mock adapter for testing network paths)
    apiClient.setConfig({ useMock: false, baseUrl: 'http://127.0.0.1:8000' });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('1. Successfully analyzes a finding with valid backend response', async () => {
    const mockBackendResponse = {
      summary: 'SQL injection confirmed on product search parameter.',
      evidence_facts: ['Observed single-quote error disclosure in HTTP 200.'],
      interpretation: ['Input passed directly into string interpolation query.'],
      severity: 'critical',
      severity_justification: 'Enables complete unauthenticated database dump.',
      confidence: 'high',
      confidence_justification: 'Empirically proven via error injection.',
      verification_status: 'confirmed',
      remediation: ['1. Use prepared statements.', '2. Validate search input.'],
      limitations: ['Did not probe blind out-of-band extraction.'],
      requires_human_review: true,
      cited_evidence_ids: ['ev_sql_001'],
      is_rule_based_fallback: false,
      analysis_provider: 'ollama:llama3.2',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockBackendResponse,
    });

    const result = await apiClient.analyzeFinding(sqliFinding, sqliEvidence);

    expect(result.summary).toBe('SQL injection confirmed on product search parameter.');
    expect(result.severity).toBe('critical');
    expect(result.confidence).toBe('high');
    expect(result.is_rule_based_fallback).toBe(false);
    expect(result.analysis_provider).toBe('ollama:llama3.2');
    expect(result.cited_evidence_ids).toEqual(['ev_sql_001']);
    expect(result.evidence_facts).toHaveLength(1);
    expect(result.remediation).toHaveLength(2);
  });

  it('2. Correctly parses and identifies deterministic fallback response', async () => {
    const mockFallbackResponse = {
      summary: 'Rule-based analysis: BOLA vulnerability detected.',
      evidence_facts: ['Captured User A accessing User B basket.'],
      interpretation: ['Missing authorization token validation.'],
      severity: 'high',
      severity_justification: 'Horizontal privilege escalation.',
      confidence: 'high',
      confidence_justification: 'Direct response code validation.',
      verification_status: 'confirmed',
      remediation: ['Enforce session.userId === basket.userId.'],
      limitations: [],
      requires_human_review: true,
      cited_evidence_ids: ['ev_bola_002'],
      is_rule_based_fallback: true,
      analysis_provider: 'deterministic_fallback',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockFallbackResponse,
    });

    const result = await apiClient.analyzeFinding(sqliFinding, sqliEvidence);

    expect(result.is_rule_based_fallback).toBe(true);
    expect(result.analysis_provider).toBe('deterministic_fallback');
  });

  it('3. Handles missing evidence without crashing and notes degradation', async () => {
    // When evidence is missing, backend or mock responds with degraded confidence
    const mockNoEvidenceResponse = {
      summary: 'Heuristic pattern check on token comparison.',
      evidence_facts: [],
      interpretation: ['Static code pattern matched non-constant time comparison.'],
      severity: 'medium',
      severity_justification: 'Theoretical cryptographic timing leak.',
      confidence: 'low',
      confidence_justification: 'Degraded to LOW due to complete absence of supporting empirical evidence.',
      verification_status: 'unverified',
      remediation: ['Use constant-time comparison API.'],
      limitations: [
        'CRITICAL EVIDENCE GAP: Zero empirical timing measurements have been captured.',
      ],
      requires_human_review: true,
      cited_evidence_ids: [],
      is_rule_based_fallback: true,
      analysis_provider: 'deterministic_fallback',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockNoEvidenceResponse,
    });

    const result = await apiClient.analyzeFinding(unverifiedFinding, emptyEvidence);

    expect(result.confidence).toBe('low');
    expect(result.verification_status).toBe('unverified');
    expect(result.cited_evidence_ids).toHaveLength(0);
    expect(result.limitations?.some((l) => l.includes('CRITICAL EVIDENCE GAP'))).toBe(true);
    // Crucial rule: original finding is unverified, AI analysis must not confirm it
    expect(result.verification_status).not.toBe('confirmed');
  });

  it('4. Handles server HTTP errors with understandable message', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({
        detail: 'Cannot mark unverified finding as confirmed without supporting evidence.',
      }),
    });

    await expect(apiClient.analyzeFinding(unverifiedFinding, emptyEvidence)).rejects.toThrow(
      'Cannot mark unverified finding as confirmed without supporting evidence.'
    );
  });

  it('5. Handles network disconnection / connection refused cleanly', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(apiClient.analyzeFinding(sqliFinding, sqliEvidence)).rejects.toThrow(
      'Unable to reach backend API at http://127.0.0.1:8000'
    );
  });

  it('6. Handles client timeout with understandable retry advice', async () => {
    const abortErr = new DOMException('The operation was aborted', 'AbortError');
    globalThis.fetch = vi.fn().mockRejectedValue(abortErr);

    await expect(apiClient.analyzeFinding(sqliFinding, sqliEvidence)).rejects.toThrow(
      'Analysis request timed out after 15 seconds. Please try again.'
    );
  });

  it('7. Development mock adapter functions when explicitly enabled', async () => {
    apiClient.setConfig({ useMock: true });

    const result = await apiClient.analyzeFinding(sqliFinding, sqliEvidence);

    expect(result.finding_id).toBe('fnd_001');
    expect(result.is_rule_based_fallback).toBe(true);
    expect(result.analysis_provider).toBe('development_mock_adapter');
    expect((result.evidence_facts || []).length).toBeGreaterThan(0);
    expect(result.summary).toContain('SQL Injection');
  });

  it('8. checkHealth returns ok: true when backend responds with 200', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: 'healthy' }),
    });

    const res = await apiClient.checkHealth();
    expect(res.ok).toBe(true);
    expect(res.status).toBe('healthy');
  });

  it('9. checkHealth returns ok: false when backend is offline or unreachable', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    const res = await apiClient.checkHealth();
    expect(res.ok).toBe(false);
    expect(res.status).toBe('unreachable');
  });

  it('10. Handles 401 Unauthorized with clear token instructions', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ detail: 'Invalid authentication token.' }),
    });

    await expect(apiClient.analyzeFinding(sqliFinding, sqliEvidence)).rejects.toThrow(
      'Authentication failed: missing or invalid API Bearer token. Please configure a valid token in Settings.'
    );
  });

  it('11. Handles 403 Forbidden with clear access instructions', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      json: async () => ({ detail: 'Forbidden' }),
    });

    await expect(apiClient.analyzeFinding(sqliFinding, sqliEvidence)).rejects.toThrow(
      'Access forbidden: current token does not possess authorization for this action.'
    );
  });
});
