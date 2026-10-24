import type { AIAnalysis, Finding, Evidence } from '../types';

export interface AnalyzeFindingPayload {
  finding: Finding;
  evidence: Evidence[];
}

export interface ApiClientConfig {
  baseUrl?: string;
  authToken?: string;
  useMock?: boolean;
}

class ApiService {
  private baseUrl: string;
  private authToken: string;
  private useMock: boolean;

  constructor() {
    // In Vite: import.meta.env
    const env = (import.meta as unknown as { env: Record<string, string | undefined> }).env || {};
    this.baseUrl = env.VITE_API_URL || 'http://127.0.0.1:8000';
    this.authToken = env.VITE_API_AUTH_TOKEN || '';
    // Development-only mock toggle: false by default when in dev or when API is reachable,
    // but can be toggled or fall back if explicitly requested
    this.useMock = env.VITE_USE_MOCK_API === 'true';
  }

  public setConfig(config: ApiClientConfig) {
    if (config.baseUrl !== undefined) this.baseUrl = config.baseUrl;
    if (config.authToken !== undefined) this.authToken = config.authToken;
    if (config.useMock !== undefined) this.useMock = config.useMock;
  }

  public isMockEnabled(): boolean {
    return this.useMock;
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Check backend health status
   */
  public async checkHealth(): Promise<{ status: string; ok: boolean }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(`${this.baseUrl}/api/health`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (response.ok) {
        return { status: 'healthy', ok: true };
      }
      return { status: `error_${response.status}`, ok: false };
    } catch {
      clearTimeout(timeoutId);
      return { status: 'unreachable', ok: false };
    }
  }

  /**
   * Deterministic local fallback generator for dev mock adapter
   */
  private generateMockAnalysis(finding: Finding, evidence: Evidence[]): AIAnalysis {
    const hasEvidence = evidence.length > 0;
    const facts = evidence.map(
      (ev) => `[${ev.source}] ${ev.description} (Observed at ${ev.observed_at})`
    );
    const interpretations = [
      `Finding "${finding.title}" originates from scanner ${finding.source_tool}.`,
      hasEvidence
        ? `Identified ${evidence.length} empirical evidence artifact(s) supporting this finding.`
        : 'CRITICAL: No empirical evidence artifacts provided. Risk deduction is theoretical.',
    ];

    const limitations: string[] = [];
    if (!hasEvidence) {
      limitations.push('ZERO EVIDENCE PROVIDED: Analysis cannot verify active exploitability.');
      limitations.push('Verification probe required to confirm vulnerability presence.');
    }

    const remediationSteps = finding.remediation
      ? [finding.remediation]
      : ['Review affected component configuration and apply vendor hardening guidelines.'];

    const summaryText = `Automated assessment of ${finding.title}: ${hasEvidence ? 'grounded in captured scanner artifacts' : 'pending empirical validation'}.`;
    const reasoningText = interpretations.join(' ');
    const remediationText = remediationSteps.join('\n');

    return {
      finding_id: finding.id,
      summary: summaryText,
      concise_summary: summaryText,
      evidence_facts: facts,
      interpretation: interpretations,
      reasoning_summary: reasoningText,
      severity: finding.severity,
      severity_assessment: finding.severity,
      severity_justification: `Derived from ${finding.source_tool} vulnerability classification and affected asset context.`,
      confidence: hasEvidence ? finding.confidence : 'low',
      confidence_assessment: hasEvidence ? finding.confidence : 'low',
      confidence_justification: hasEvidence
        ? `Grounded in ${evidence.length} attached evidence record(s).`
        : 'Degraded to LOW due to complete absence of supporting empirical evidence.',
      verification_status: finding.verification_status,
      remediation: remediationSteps,
      recommended_remediation: remediationText,
      limitations: limitations,
      limitations_and_missing_evidence: limitations,
      requires_human_review: true,
      cited_evidence_ids: evidence.map((e) => e.id),
      is_rule_based_fallback: true,
      analysis_provider: 'development_mock_adapter',
    };
  }

  /**
   * Post finding & evidence to the backend /api/ai/analyze endpoint
   */
  public async analyzeFinding(finding: Finding, evidence: Evidence[]): Promise<AIAnalysis> {
    // If mock is explicitly forced in development environment
    if (this.useMock) {
      // Small realistic async latency
      await new Promise((resolve) => setTimeout(resolve, 600));
      return this.generateMockAnalysis(finding, evidence);
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
      headers['X-API-Key'] = this.authToken;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s client timeout

    try {
      const response = await fetch(`${this.baseUrl}/api/ai/analyze`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          finding,
          evidence,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errMessage = `Server error HTTP ${response.status}`;
        try {
          const errData = await response.json();
          if (errData.detail) {
            errMessage = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
          }
        } catch {
          // fallback to status text
          errMessage = response.statusText || errMessage;
        }
        throw new Error(errMessage);
      }

      const rawData = await response.json();

      const summ = rawData.summary || rawData.concise_summary || 'Analysis completed.';
      const interps = Array.isArray(rawData.interpretation)
        ? rawData.interpretation
        : rawData.reasoning_summary
        ? [rawData.reasoning_summary]
        : [];
      const rems = Array.isArray(rawData.remediation)
        ? rawData.remediation
        : rawData.recommended_remediation
        ? [rawData.recommended_remediation]
        : [];
      const limits = Array.isArray(rawData.limitations)
        ? rawData.limitations
        : Array.isArray(rawData.limitations_and_missing_evidence)
        ? rawData.limitations_and_missing_evidence
        : [];
      const sev = rawData.severity || rawData.severity_assessment || finding.severity;
      const conf = rawData.confidence || rawData.confidence_assessment || finding.confidence;

      // Normalize fields if backend returned slight naming differences
      const normalized: AIAnalysis = {
        finding_id: finding.id,
        summary: summ,
        concise_summary: summ,
        evidence_facts: Array.isArray(rawData.evidence_facts) ? rawData.evidence_facts : [],
        interpretation: interps,
        reasoning_summary: interps.join(' '),
        severity: sev,
        severity_assessment: sev,
        severity_justification: rawData.severity_justification || 'Evaluated against security policy.',
        confidence: conf,
        confidence_assessment: conf,
        confidence_justification: rawData.confidence_justification || 'Based on available evidence.',
        verification_status: rawData.verification_status || finding.verification_status,
        remediation: rems,
        recommended_remediation: rems.join('\n'),
        limitations: limits,
        limitations_and_missing_evidence: limits,
        requires_human_review: rawData.requires_human_review ?? true,
        cited_evidence_ids: rawData.cited_evidence_ids || [],
        is_rule_based_fallback: rawData.is_rule_based_fallback ?? false,
        analysis_provider: rawData.analysis_provider || 'backend_service',
      };

      return normalized;
    } catch (err: unknown) {
      clearTimeout(timeoutId);

      // Distinguish AbortError
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new Error('Analysis request timed out after 15 seconds. Please try again.');
      }

      if (err instanceof TypeError && err.message.includes('fetch')) {
        throw new Error(
          `Unable to reach backend API at ${this.baseUrl}. Verify that the backend server is running.`
        );
      }

      throw err;
    }
  }
  /**
   * Check status of connected security and OSINT modules
   */
  public async getModuleStatuses(): Promise<{
    orchestrator_status: string;
    osint_status: string;
    scanner_status: string;
    details: any;
  }> {
    if (this.useMock) {
      return {
        orchestrator_status: 'connected',
        osint_status: 'connected',
        scanner_status: 'connected',
        details: 'Mock Mode',
      };
    }

    try {
      const response = await fetch(`${this.baseUrl}/api/upstream/modules`, {
        headers: this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {},
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch {
      return {
        orchestrator_status: 'not_connected',
        osint_status: 'not_connected',
        scanner_status: 'not_connected',
        details: 'Upstream module unreachable',
      };
    }
  }

  /**
   * Normalizes raw OSINT and scanner payload through the adapter
   */
  public async normalizeUpstreamPayload(payload: {
    assessment?: any;
    assets?: any[];
    findings?: any[];
    evidence?: any[];
    fallback_assessment_id?: string;
  }): Promise<{
    assessment: any;
    assets: any[];
    findings: any[];
    evidence: any[];
  }> {
    const response = await fetch(`${this.baseUrl}/api/upstream/normalize`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {}),
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Normalization error: HTTP ${response.status}`);
    }

    return await response.json();
  }
}

export const apiClient = new ApiService();
