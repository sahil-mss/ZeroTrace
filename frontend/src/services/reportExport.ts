import type { Assessment, Asset, Finding, Evidence, AIAnalysis } from '../types';

export interface AssessmentReportData {
  metadata: {
    platform: string;
    version: string;
    generated_at: string;
  };
  assessment: {
    id: string;
    name: string;
    target: string;
    status: string;
    created_at: string;
    completed_at?: string;
    scope_policy: string;
    allowed_checks: string[];
  };
  executive_summary: string;
  scope_and_methodology: {
    policy: string;
    target: string;
    allowed_checks: string[];
    observed_services_count: number;
    recorded_evidence_count: number;
    activity_count: number;
  };
  asset_inventory: {
    total: number;
    items: {
      id: string;
      hostname_or_address: string;
      asset_type: string;
      source: string;
      observed_at: string;
      services: {
        port: number;
        protocol: string;
        service_name?: string;
        banner?: string;
      }[];
    }[];
  };
  findings_summary: {
    total: number;
    by_severity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      informational: number;
    };
    by_verification: {
      confirmed: number;
      likely: number;
      unverified: number;
      false_positive: number;
    };
  };
  finding_details: {
    id: string;
    title: string;
    description: string;
    affected_asset: string;
    severity: string;
    confidence: string;
    verification_status: string;
    taxonomy: string;
    source_tool: string;
    evidence_references: string[];
    remediation: string;
    ai_interpretation?: {
      summary: string;
      evidence_facts: string[];
      interpretation: string[];
      severity_justification: string;
      confidence_justification: string;
      limitations: string[];
      is_fallback: boolean;
      provider: string;
    };
  }[];
  limitations_and_gaps: {
    unverified_findings_count: number;
    findings_without_evidence_count: number;
    documented_items: {
      finding_id: string;
      title: string;
      reason: string;
      limitations: string[];
    }[];
  };
  remediation_checklist: {
    priority: number;
    finding_id: string;
    title: string;
    severity: string;
    verification_status: string;
    action: string;
  }[];
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

/**
 * Escapes HTML characters to prevent XSS in rendered HTML reports.
 */
export function escapeHtml(str: string | null | undefined): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Compiles a structured, grounded report model exclusively from stored data.
 */
export function compileAssessmentReport(
  assessment: Assessment | undefined,
  allAssets: Asset[],
  allFindings: Finding[],
  allEvidence: Evidence[],
  aiAnalysisRecord: Record<string, AIAnalysis>
): AssessmentReportData | null {
  if (!assessment) return null;

  const assessmentId = assessment.id;
  const assets = allAssets.filter((a) => a.assessment_id === assessmentId);
  const findings = allFindings.filter((f) => f.assessment_id === assessmentId);
  const evidenceIds = new Set(findings.flatMap((f) => f.evidence_references));
  const relevantEvidence = allEvidence.filter((e) => evidenceIds.has(e.id));

  // Severity counts
  const by_severity = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    informational: findings.filter((f) => f.severity === 'informational').length,
  };

  // Verification counts
  const by_verification = {
    confirmed: findings.filter((f) => f.verification_status === 'confirmed').length,
    likely: findings.filter((f) => f.verification_status === 'likely').length,
    unverified: findings.filter((f) => f.verification_status === 'unverified').length,
    false_positive: findings.filter((f) => f.verification_status === 'false_positive').length,
  };

  // Sorted findings: Critical first, then High, etc.
  const sortedFindings = [...findings].sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return a.title.localeCompare(b.title);
  });

  // Executive summary strictly grounded in counts and target
  let executiveSummary = '';
  if (findings.length === 0) {
    executiveSummary = `A security assessment was performed for "${assessment.name}" against target ${assessment.target} under scope policy ${assessment.scope_policy}. Currently, zero vulnerability records have been logged in the assessment dataset. Ongoing monitoring or active scan execution is required to establish comprehensive vulnerability findings.`;
  } else {
    executiveSummary = `A security evaluation was conducted for "${assessment.name}" against the authorized target ${assessment.target} under the ${assessment.scope_policy} policy. A total of ${findings.length} findings were recorded across ${assets.length} identified assets. Testing empirically confirmed ${by_verification.confirmed} vulnerabilities, while ${by_verification.unverified} finding(s) remain unverified pending empirical probes. Immediate remediation is prioritized for ${by_severity.critical} Critical and ${by_severity.high} High severity issues to safeguard application and system boundaries.`;
  }

  // Finding details
  const finding_details = sortedFindings.map((f) => {
    const ai = aiAnalysisRecord[f.id];
    let ai_interpretation = undefined;

    if (ai) {
      ai_interpretation = {
        summary: ai.summary || ai.concise_summary || '',
        evidence_facts: ai.evidence_facts || [],
        interpretation: ai.interpretation || (ai.reasoning_summary ? [ai.reasoning_summary] : []),
        severity_justification: ai.severity_justification || '',
        confidence_justification: ai.confidence_justification || '',
        limitations: ai.limitations || ai.limitations_and_missing_evidence || [],
        is_fallback: ai.is_rule_based_fallback ?? false,
        provider: ai.analysis_provider || (ai.is_rule_based_fallback ? 'deterministic_fallback' : 'configured_model'),
      };
    }

    const taxonomyParts: string[] = [];
    if (f.cwe) taxonomyParts.push(f.cwe);
    if (f.cve) taxonomyParts.push(`(${f.cve})`);

    return {
      id: f.id,
      title: f.title,
      description: f.description,
      affected_asset: f.asset_id || 'Target Scope',
      severity: f.severity,
      confidence: f.confidence,
      verification_status: f.verification_status,
      taxonomy: taxonomyParts.join(' ') || 'Standard Security Check',
      source_tool: f.source_tool,
      evidence_references: f.evidence_references,
      remediation: f.remediation || 'Refer to secure development guidelines.',
      ai_interpretation,
    };
  });

  // Limitations & Gaps
  const documented_items: AssessmentReportData['limitations_and_gaps']['documented_items'] = [];
  let unverifiedCount = 0;
  let missingEvidenceCount = 0;

  findings.forEach((f) => {
    const isUnverified = f.verification_status === 'unverified';
    const noEvidence = f.evidence_references.length === 0;
    const ai = aiAnalysisRecord[f.id];

    if (isUnverified) unverifiedCount++;
    if (noEvidence) missingEvidenceCount++;

    if (isUnverified || noEvidence || (ai && (ai.limitations || ai.limitations_and_missing_evidence || []).length > 0)) {
      const reasons: string[] = [];
      if (isUnverified) reasons.push('Status is UNVERIFIED: No dynamic exploit or manual verification confirmed.');
      if (noEvidence) reasons.push('Zero raw evidence payloads attached to finding record.');

      const aiLimits = ai?.limitations || ai?.limitations_and_missing_evidence || [];
      documented_items.push({
        finding_id: f.id,
        title: f.title,
        reason: reasons.join(' '),
        limitations: aiLimits,
      });
    }
  });

  // Prioritized Remediation Checklist
  const remediation_checklist = sortedFindings
    .filter((f) => f.verification_status !== 'false_positive')
    .map((f, idx) => ({
      priority: idx + 1,
      finding_id: f.id,
      title: f.title,
      severity: f.severity,
      verification_status: f.verification_status,
      action: f.remediation || 'Conduct code review and implement defensive controls.',
    }));

  return {
    metadata: {
      platform: 'ZeroTrace / AegisPT Security Suite',
      version: '1.0.0',
      generated_at: new Date().toISOString(),
    },
    assessment: {
      id: assessment.id,
      name: assessment.name,
      target: assessment.target,
      status: assessment.status,
      created_at: assessment.created_at,
      completed_at: assessment.completed_at,
      scope_policy: assessment.scope_policy,
      allowed_checks: assessment.allowed_checks,
    },
    executive_summary: executiveSummary,
    scope_and_methodology: {
      policy: assessment.scope_policy,
      target: assessment.target,
      allowed_checks: assessment.allowed_checks,
      observed_services_count: assets.reduce(
        (acc, curr) => acc + (curr.discovered_services?.length || 0),
        0
      ),
      recorded_evidence_count: relevantEvidence.length,
      activity_count: 0,
    },
    asset_inventory: {
      total: assets.length,
      items: assets.map((a) => ({
        id: a.id,
        hostname_or_address: a.hostname_or_address,
        asset_type: a.asset_type,
        source: a.source,
        observed_at: a.observed_at,
        services: a.discovered_services || [],
      })),
    },
    findings_summary: {
      total: findings.length,
      by_severity,
      by_verification,
    },
    finding_details,
    limitations_and_gaps: {
      unverified_findings_count: unverifiedCount,
      findings_without_evidence_count: missingEvidenceCount,
      documented_items,
    },
    remediation_checklist,
  };
}

/**
 * Downloads a structured JSON export file.
 */
export function exportReportJSON(report: AssessmentReportData, filename?: string): void {
  const name = filename || `Report_${report.assessment.id}_${Date.now()}.json`;
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: 'application/json;charset=utf-8;',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', name);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Generates an executive Markdown report text.
 */
export function generateReportMarkdown(report: AssessmentReportData): string {
  const { assessment, findings_summary, asset_inventory, finding_details, remediation_checklist, limitations_and_gaps } =
    report;

  let md = `# Security Assessment Report: ${assessment.name}\n\n`;
  md += `**Target Scope:** \`${assessment.target}\`\n`;
  md += `**Assessment Identifier:** \`${assessment.id}\`\n`;
  md += `**Scope Policy:** \`${assessment.scope_policy}\`\n`;
  md += `**Status:** ${assessment.status.toUpperCase()}\n`;
  md += `**Created Timestamp:** ${assessment.created_at}\n`;
  if (assessment.completed_at) {
    md += `**Completed Timestamp:** ${assessment.completed_at}\n`;
  }
  md += `**Report Generated:** ${report.metadata.generated_at}\n\n`;

  md += `## 1. Executive Summary\n\n${report.executive_summary}\n\n`;

  md += `## 2. Scope & Methodology\n\n`;
  md += `- **Authorized Target:** \`${assessment.target}\`\n`;
  md += `- **Scope Policy Enforcement:** \`${assessment.scope_policy}\`\n`;
  md += `- **Permitted Scan Profiles:** ${assessment.allowed_checks.map((c) => `\`${c}\``).join(', ')}\n`;
  md += `- **Total Assets Evaluated:** ${asset_inventory.total}\n`;
  md += `- **Services Observed:** ${report.scope_and_methodology.observed_services_count}\n`;
  md += `- **Empirical Evidence Records:** ${report.scope_and_methodology.recorded_evidence_count}\n\n`;

  md += `## 3. Asset Inventory\n\n`;
  if (asset_inventory.items.length === 0) {
    md += `*No asset inventory records logged for this assessment.*\n\n`;
  } else {
    md += `| Asset Identifier | Hostname / Address | Type | Discovery Source | Services |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;
    asset_inventory.items.forEach((a) => {
      const svcs = a.services.map((s) => `${s.port}/${s.protocol} (${s.service_name || 'unknown'})`).join(', ') || 'None';
      md += `| \`${a.id}\` | \`${a.hostname_or_address}\` | ${a.asset_type} | ${a.source} | ${svcs} |\n`;
    });
    md += `\n`;
  }

  md += `## 4. Findings Summary\n\n`;
  md += `Total Findings: **${findings_summary.total}**\n\n`;
  md += `| Severity | Count | Verification Status | Count |\n`;
  md += `| :--- | :--- | :--- | :--- |\n`;
  md += `| Critical | ${findings_summary.by_severity.critical} | Confirmed | ${findings_summary.by_verification.confirmed} |\n`;
  md += `| High | ${findings_summary.by_severity.high} | Likely | ${findings_summary.by_verification.likely} |\n`;
  md += `| Medium | ${findings_summary.by_severity.medium} | Unverified | ${findings_summary.by_verification.unverified} |\n`;
  md += `| Low | ${findings_summary.by_severity.low} | False Positive | ${findings_summary.by_verification.false_positive} |\n`;
  md += `| Informational | ${findings_summary.by_severity.informational} | | |\n\n`;

  md += `## 5. Detailed Technical Findings\n\n`;
  if (finding_details.length === 0) {
    md += `*No findings recorded for this assessment.*\n\n`;
  } else {
    finding_details.forEach((f, idx) => {
      md += `### 5.${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
      md += `- **Finding ID:** \`${f.id}\`\n`;
      md += `- **Affected Asset:** \`${f.affected_asset}\`\n`;
      md += `- **Severity:** ${f.severity.toUpperCase()} | **Confidence:** ${f.confidence.toUpperCase()}\n`;
      md += `- **Verification Status:** ${f.verification_status.toUpperCase()}\n`;
      md += `- **Taxonomy:** ${f.taxonomy}\n`;
      md += `- **Source Tool:** ${f.source_tool}\n`;
      md += `- **Evidence References:** ${f.evidence_references.length > 0 ? f.evidence_references.map((id) => `\`${id}\``).join(', ') : '*None (Evidence Absent)*'}\n\n`;
      md += `**Description:**\n${f.description}\n\n`;

      if (f.ai_interpretation) {
        md += `> **AI Interpretation (${f.ai_interpretation.is_fallback ? 'Deterministic Fallback' : 'Configured Model: ' + f.ai_interpretation.provider}):**\n`;
        md += `> - **Summary:** ${f.ai_interpretation.summary}\n`;
        if (f.ai_interpretation.interpretation.length > 0) {
          f.ai_interpretation.interpretation.forEach((interp) => {
            md += `> - ${interp}\n`;
          });
        }
        md += `> - **Severity Rationale:** ${f.ai_interpretation.severity_justification}\n`;
        md += `> - **Confidence Rationale:** ${f.ai_interpretation.confidence_justification}\n\n`;
      }

      md += `**Remediation Guidance:**\n${f.remediation}\n\n`;
      md += `---\n\n`;
    });
  }

  md += `## 6. Limitations, Missing Evidence & Unverified Findings\n\n`;
  if (limitations_and_gaps.documented_items.length === 0) {
    md += `*All findings have verified empirical evidence. No evidence gaps identified.*\n\n`;
  } else {
    md += `- Unverified findings pending validation: **${limitations_and_gaps.unverified_findings_count}**\n`;
    md += `- Findings lacking empirical evidence: **${limitations_and_gaps.findings_without_evidence_count}**\n\n`;
    limitations_and_gaps.documented_items.forEach((item) => {
      md += `### Limitation: ${item.title} (\`${item.finding_id}\`)\n`;
      if (item.reason) md += `- **Audit Status:** ${item.reason}\n`;
      item.limitations.forEach((lim) => {
        md += `- **Scope Limitation:** ${lim}\n`;
      });
      md += `\n`;
    });
  }

  md += `## 7. Prioritized Remediation Checklist\n\n`;
  if (remediation_checklist.length === 0) {
    md += `*No actionable remediation items required.*\n\n`;
  } else {
    md += `| Priority | Finding ID | Severity | Verification Status | Title & Action |\n`;
    md += `| :---: | :--- | :--- | :--- | :--- |\n`;
    remediation_checklist.forEach((item) => {
      md += `| **#${item.priority}** | \`${item.finding_id}\` | ${item.severity.toUpperCase()} | ${item.verification_status} | **${item.title}**: ${item.action} |\n`;
    });
    md += `\n`;
  }

  return md;
}

/**
 * Downloads a structured Markdown export file.
 */
export function exportReportMarkdown(report: AssessmentReportData, filename?: string): void {
  const name = filename || `Report_${report.assessment.id}_${Date.now()}.md`;
  const md = generateReportMarkdown(report);
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', name);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
