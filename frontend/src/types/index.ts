export type AssessmentStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';

export type AssetType = 'domain' | 'ip' | 'web_app' | 'api_endpoint' | 'service' | 'other';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type VerificationStatus = 'confirmed' | 'likely' | 'unverified' | 'false_positive';

export interface DiscoveredService {
  port: number;
  protocol: string;
  service_name?: string;
  banner?: string;
}

export interface Assessment {
  id: string;
  name: string;
  target: string;
  status: AssessmentStatus;
  created_at: string;
  completed_at?: string;
  scope_policy: string;
  allowed_checks: string[];
}

export interface Asset {
  id: string;
  assessment_id: string;
  hostname_or_address: string;
  asset_type: AssetType;
  discovered_services: DiscoveredService[];
  source: string;
  observed_at: string;
}

export interface Evidence {
  id: string;
  source: string;
  description: string;
  observed_at: string;
  asset_id?: string;
  reference_or_artifact_location?: string;
  raw_data?: string;
}

export interface Finding {
  id: string;
  assessment_id: string;
  asset_id?: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: ConfidenceLevel;
  verification_status: VerificationStatus;
  evidence_references: string[];
  remediation?: string;
  source_tool: string;
  cve?: string;
  cwe?: string;
  first_seen: string;
  last_seen: string;
}

export interface AIAnalysis {
  finding_id: string;
  // Core schema fields
  summary?: string;
  evidence_facts?: string[];
  interpretation?: string[];
  severity?: FindingSeverity;
  severity_justification: string;
  confidence?: ConfidenceLevel;
  confidence_justification: string;
  verification_status?: VerificationStatus;
  remediation?: string[];
  limitations?: string[];
  requires_human_review?: boolean;
  cited_evidence_ids: string[];
  is_rule_based_fallback?: boolean;
  analysis_provider?: string;

  // Backward compatibility aliases
  concise_summary: string;
  reasoning_summary: string;
  severity_assessment: FindingSeverity;
  confidence_assessment: ConfidenceLevel;
  recommended_remediation: string;
  limitations_and_missing_evidence: string[];
}

export interface ActivityEvent {
  id: string;
  assessment_id: string;
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'success';
  component: 'SCOPE_ENGINE' | 'OSINT_ADAPTER' | 'SCANNER_WORKER' | 'AI_REASONER' | 'REPORT_GENERATOR';
  message: string;
  details?: string;
}

export interface ToastMessage {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message?: string;
}
