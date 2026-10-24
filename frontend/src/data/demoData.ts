import type {
  Assessment,
  Asset,
  Evidence,
  Finding,
  AIAnalysis,
  ActivityEvent,
} from '../types';

export const DEMO_BANNER_LABEL = '[DEMO LAB DATA — CONTROLLED TEST ENVIRONMENT]';

export const DEMO_ASSESSMENTS: Assessment[] = [
  {
    id: 'asm_lab_001',
    name: 'OWASP Juice Shop (Lab Assessment)',
    target: 'http://127.0.0.1:3000',
    status: 'in_progress',
    created_at: '2026-10-24T18:30:00Z',
    scope_policy: 'STRICT_SINGLE_HOST',
    allowed_checks: ['passive_recon', 'port_scan', 'web_active_inspection'],
  },
  {
    id: 'asm_lab_002',
    name: 'Local DVWA Security Sandbox',
    target: 'http://10.0.4.15:8080',
    status: 'completed',
    created_at: '2026-10-24T14:15:00Z',
    completed_at: '2026-10-24T15:05:00Z',
    scope_policy: 'LAB_SUBNET_CONSTRAINED',
    allowed_checks: ['passive_recon', 'port_scan'],
  },
  {
    id: 'asm_lab_003',
    name: 'Internal OAuth Gateway Staging',
    target: 'https://auth-stage.internal.corp',
    status: 'pending',
    created_at: '2026-10-24T19:00:00Z',
    scope_policy: 'EXPLICIT_HOST_ALLOWLIST',
    allowed_checks: ['passive_recon'],
  },
];

export const DEMO_ASSETS: Asset[] = [
  {
    id: 'ast_001',
    assessment_id: 'asm_lab_001',
    hostname_or_address: '127.0.0.1:3000',
    asset_type: 'web_app',
    source: 'nmap_service_probe',
    observed_at: '2026-10-24T18:31:10Z',
    discovered_services: [
      { port: 3000, protocol: 'tcp', service_name: 'http', banner: 'Express.js / Node.js 20.x' },
    ],
  },
  {
    id: 'ast_002',
    assessment_id: 'asm_lab_001',
    hostname_or_address: 'http://127.0.0.1:3000/rest/admin',
    asset_type: 'api_endpoint',
    source: 'web_spider_crawler',
    observed_at: '2026-10-24T18:33:45Z',
    discovered_services: [],
  },
  {
    id: 'ast_003',
    assessment_id: 'asm_lab_001',
    hostname_or_address: 'http://127.0.0.1:3000/api/Users',
    asset_type: 'api_endpoint',
    source: 'zap_spider',
    observed_at: '2026-10-24T18:34:12Z',
    discovered_services: [],
  },
  {
    id: 'ast_004',
    assessment_id: 'asm_lab_001',
    hostname_or_address: '127.0.0.1:27017',
    asset_type: 'service',
    source: 'nmap_service_probe',
    observed_at: '2026-10-24T18:32:05Z',
    discovered_services: [
      { port: 27017, protocol: 'tcp', service_name: 'mongodb', banner: 'MongoDB 6.0 Server' },
    ],
  },
  {
    id: 'ast_005',
    assessment_id: 'asm_lab_002',
    hostname_or_address: '10.0.4.15:8080',
    asset_type: 'web_app',
    source: 'nmap_service_probe',
    observed_at: '2026-10-24T14:16:00Z',
    discovered_services: [
      { port: 8080, protocol: 'tcp', service_name: 'http', banner: 'Apache/2.4.52 (Ubuntu)' },
      { port: 3306, protocol: 'tcp', service_name: 'mysql', banner: 'MySQL 8.0.32' },
    ],
  },
];

export const DEMO_EVIDENCE: Evidence[] = [
  {
    id: 'ev_sql_001',
    source: 'owasp_zap',
    description: 'Active SQL injection reflection in search parameter q on /rest/products/search',
    observed_at: '2026-10-24T18:36:20Z',
    asset_id: 'ast_001',
    reference_or_artifact_location: '/artifacts/scans/zap_search_sqli.json',
    raw_data:
      'GET /rest/products/search?q=\'))%20UNION%20SELECT%20id,email,password%20FROM%20Users-- HTTP/1.1\nHost: 127.0.0.1:3000\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n[{"id":1,"email":"admin@juice-sh.op","password":"0192023a7bbd73250516f069df18b500"}]',
  },
  {
    id: 'ev_bola_002',
    source: 'custom_verifier',
    description: 'Unauthorized access to order basket id=2 belonging to a different customer ID',
    observed_at: '2026-10-24T18:38:12Z',
    asset_id: 'ast_001',
    reference_or_artifact_location: '/artifacts/scans/basket_bola_proof.json',
    raw_data:
      'GET /rest/basket/2 HTTP/1.1\nHost: 127.0.0.1:3000\nAuthorization: Bearer <user_token_id_3>\n\nHTTP/1.1 200 OK\n{"data":{"id":2,"UserId":2,"Products":[{"id":4,"name":"Juice Pack"}]}}',
  },
  {
    id: 'ev_headers_003',
    source: 'nmap_http_headers',
    description: 'Missing Strict-Transport-Security (HSTS) and Content-Security-Policy headers',
    observed_at: '2026-10-24T18:32:00Z',
    asset_id: 'ast_001',
    reference_or_artifact_location: '/artifacts/scans/headers_check.txt',
    raw_data:
      'HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\n(Strict-Transport-Security header omitted)\n(Content-Security-Policy header omitted)',
  },
  {
    id: 'ev_leak_004',
    source: 'passive_crawler',
    description: 'Verbose stack trace disclosing backend file paths upon sending malformed JSON',
    observed_at: '2026-10-24T18:40:05Z',
    asset_id: 'ast_002',
    reference_or_artifact_location: '/artifacts/scans/stack_trace_leak.log',
    raw_data:
      'HTTP/1.1 500 Internal Server Error\nError: Unexpected token < at Object.parse (/server/node_modules/body-parser/lib/types/json.js:89:19)',
  },
  {
    id: 'ev_fp_005',
    source: 'nuclei_engine',
    description: 'Heuristic pattern match for path traversal against static asset handler',
    observed_at: '2026-10-24T18:42:00Z',
    asset_id: 'ast_001',
    reference_or_artifact_location: '/artifacts/scans/nuclei_traversal.log',
    raw_data:
      'GET /assets/public/..%2f..%2fpackage.json HTTP/1.1\n\nHTTP/1.1 403 Forbidden\nAccess Denied by Express Static Safe Resolver',
  },
];

export const DEMO_FINDINGS: Finding[] = [
  {
    id: 'fnd_001',
    assessment_id: 'asm_lab_001',
    asset_id: 'ast_001',
    title: 'Union-Based SQL Injection in Product Search Query',
    description:
      'The search parameter `q` is directly concatenated into a backend SQL query without sanitization or parameterization, allowing unauthenticated attackers to dump full user records and database contents.',
    severity: 'critical',
    confidence: 'high',
    verification_status: 'confirmed',
    evidence_references: ['ev_sql_001'],
    remediation:
      'Use parameterized queries or prepared statements via SQLite/Sequelize ORM. Never concatenate raw request parameters directly into database queries.',
    source_tool: 'owasp_zap',
    cve: 'CVE-2024-SQLI-LAB',
    cwe: 'CWE-89',
    first_seen: '2026-10-24T18:36:20Z',
    last_seen: '2026-10-24T18:36:20Z',
  },
  {
    id: 'fnd_002',
    assessment_id: 'asm_lab_001',
    asset_id: 'ast_001',
    title: 'Broken Object Level Authorization (BOLA) in Order Basket API',
    description:
      'The `/rest/basket/{id}` endpoint permits authenticated users to access other users shopping carts and customer information by simply substituting numeric ID values.',
    severity: 'high',
    confidence: 'high',
    verification_status: 'confirmed',
    evidence_references: ['ev_bola_002'],
    remediation:
      'Enforce record-level authorization checks: verify that the authenticated user session matches the customer ID associated with the requested basket ID before returning data.',
    source_tool: 'custom_verifier',
    cwe: 'CWE-285',
    first_seen: '2026-10-24T18:38:12Z',
    last_seen: '2026-10-24T18:38:12Z',
  },
  {
    id: 'fnd_003',
    assessment_id: 'asm_lab_001',
    asset_id: 'ast_001',
    title: 'Missing HTTP Strict Transport Security (HSTS) Header',
    description:
      'The web server does not supply an HSTS header (`Strict-Transport-Security`), leaving users susceptible to man-in-the-middle downgrade attacks on insecure network connections.',
    severity: 'low',
    confidence: 'high',
    verification_status: 'confirmed',
    evidence_references: ['ev_headers_003'],
    remediation:
      'Configure the web server or reverse proxy to inject `Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
    source_tool: 'nmap_http_headers',
    cwe: 'CWE-319',
    first_seen: '2026-10-24T18:32:00Z',
    last_seen: '2026-10-24T18:32:00Z',
  },
  {
    id: 'fnd_004',
    assessment_id: 'asm_lab_001',
    asset_id: 'ast_002',
    title: 'Detailed Stack Trace Disclosed in HTTP 500 Responses',
    description:
      'Malformed payload handling triggers an unhandled exception handler that exposes server-side file structures and component library paths to end users.',
    severity: 'informational',
    confidence: 'medium',
    verification_status: 'likely',
    evidence_references: ['ev_leak_004'],
    remediation:
      'Ensure standard production error handling is enabled. Replace verbose stack traces with generalized error pages and log technical details internally.',
    source_tool: 'passive_crawler',
    cwe: 'CWE-209',
    first_seen: '2026-10-24T18:40:05Z',
    last_seen: '2026-10-24T18:40:05Z',
  },
  {
    id: 'fnd_006',
    assessment_id: 'asm_lab_001',
    asset_id: 'ast_001',
    title: 'Potential Timing-Based Side Channel in Token Comparison',
    description:
      'Static analysis flagged non-constant-time string comparison in reset password verification. However, no active timing measurements or empirical evidence have been collected.',
    severity: 'medium',
    confidence: 'low',
    verification_status: 'unverified',
    evidence_references: [],
    remediation:
      'Use `crypto.timingSafeEqual` in Node.js instead of standard equality operators for security tokens.',
    source_tool: 'semgrep_ruleset',
    cwe: 'CWE-208',
    first_seen: '2026-10-24T18:41:00Z',
    last_seen: '2026-10-24T18:41:00Z',
  },
  {
    id: 'fnd_007',
    assessment_id: 'asm_lab_001',
    asset_id: 'ast_001',
    title: 'Heuristic Path Traversal in Static Asset Router',
    description:
      'Scanner flagged potential path traversal on `/assets/public/`. Verification probe confirmed the web server returns HTTP 403 Forbidden and normalizes paths safely, proving this is a false positive.',
    severity: 'high',
    confidence: 'low',
    verification_status: 'false_positive',
    evidence_references: ['ev_fp_005'],
    remediation:
      'No application code fix needed; scanner rule threshold should be tuned to require non-403 responses.',
    source_tool: 'nuclei_engine',
    cwe: 'CWE-22',
    first_seen: '2026-10-24T18:42:00Z',
    last_seen: '2026-10-24T18:42:00Z',
  },
  {
    id: 'fnd_005',
    assessment_id: 'asm_lab_002',
    asset_id: 'ast_005',
    title: 'Command Execution Vulnerability in Ping Utility',
    description:
      'The DVWA ping utility accepts unescaped semicolon command chaining delimiters, allowing local code execution under web daemon context.',
    severity: 'critical',
    confidence: 'high',
    verification_status: 'confirmed',
    evidence_references: [],
    remediation:
      'Use strictly validated IP address regexes and system APIs instead of invoking shell commands directly with string concatenation.',
    source_tool: 'owasp_zap',
    cwe: 'CWE-78',
    first_seen: '2026-10-24T14:35:00Z',
    last_seen: '2026-10-24T14:35:00Z',
  },
];

export const DEMO_AI_ANALYSIS: Record<string, AIAnalysis> = {
  fnd_001: {
    finding_id: 'fnd_001',
    concise_summary:
      'Exploitable SQL injection vulnerability enabling complete compromise of application confidentiality and integrity.',
    reasoning_summary:
      'Evidence `ev_sql_001` empirically confirms database response to a UNION SELECT payload. Injected single quote breaks out of the intended string literal, and the returned HTTP 200 contains the admin password hash from the Users table.',
    severity_assessment: 'critical',
    severity_justification:
      'Direct, unauthenticated database readout includes administrator credentials and private customer records.',
    confidence_assessment: 'high',
    confidence_justification:
      'Demonstrated data extraction payload executed successfully in the lab target without false-positive ambiguity.',
    recommended_remediation:
      '1. Immediately refactor `/rest/products/search` to utilize prepared statements.\n2. Apply input whitelisting for allowable search filter characters.\n3. Ensure least-privilege database user permissions.',
    limitations_and_missing_evidence: [
      'Database write privileges (INSERT/UPDATE/DELETE) were not probed to avoid altering lab state.',
      'Underlying DBMS version was inferred from syntax behavior but not explicitly fingerprinted.',
    ],
    cited_evidence_ids: ['ev_sql_001'],
  },
  fnd_002: {
    finding_id: 'fnd_002',
    concise_summary:
      'Broken object-level authorization allows horizontal privilege escalation across customer baskets.',
    reasoning_summary:
      'Evidence `ev_bola_002` documents that a token issued for User #3 successfully retrieved cart contents and personal data for User #2 without rejection.',
    severity_assessment: 'high',
    severity_justification:
      'Leads to cross-tenant information exposure and potential tampering with order processing.',
    confidence_assessment: 'high',
    confidence_justification:
      'Verified with two distinct user session tokens under controlled conditions.',
    recommended_remediation:
      'Implement an access-control middleware verifying `session.userId === basket.UserId` prior to query execution.',
    limitations_and_missing_evidence: [
      'Check if payment credentials or billing addresses are also stored on the basket object.',
    ],
    cited_evidence_ids: ['ev_bola_002'],
  },
  fnd_003: {
    finding_id: 'fnd_003',
    concise_summary:
      'Absence of HSTS header leaves client traffic vulnerable to SSL-stripping over insecure networks.',
    reasoning_summary:
      'Header inspection in `ev_headers_003` confirms that responses lack Strict-Transport-Security headers.',
    severity_assessment: 'low',
    severity_justification:
      'Requires active network-level interception (MITM) to exploit, but represents deviation from cryptographic standards.',
    confidence_assessment: 'high',
    confidence_justification:
      'Direct passive observation of raw HTTP response headers.',
    recommended_remediation:
      'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header in web server configuration.',
    limitations_and_missing_evidence: [
      'Lab environment currently executes on plain HTTP port 3000; HSTS only applies when HTTPS is active.',
    ],
    cited_evidence_ids: ['ev_headers_003'],
  },
  fnd_004: {
    finding_id: 'fnd_004',
    concise_summary:
      'Server error disclosure leaks directory layout and runtime framework dependencies.',
    reasoning_summary:
      'Evidence `ev_leak_004` exhibits raw Node.js runtime traces mentioning internal library paths.',
    severity_assessment: 'informational',
    severity_justification:
      'Provides reconnaissance intelligence to attackers but does not directly allow exploitation on its own.',
    confidence_assessment: 'medium',
    confidence_justification:
      'Trace observed once during malformed JSON fuzzing.',
    recommended_remediation:
      'Set `NODE_ENV=production` and configure generic error handling middleware.',
    limitations_and_missing_evidence: [
      'Need to test whether error disclosure persists across other API endpoints.',
    ],
    cited_evidence_ids: ['ev_leak_004'],
  },
  fnd_006: {
    finding_id: 'fnd_006',
    concise_summary:
      'Unverified code pattern suspicion: Potential timing discrepancy in token comparison.',
    reasoning_summary:
      'Scanner flagged syntax equality operator on tokens. IMPORTANT: No network timing evidence or empirical proof exists. AI analysis cannot confirm this vulnerability without controlled empirical timing measurement.',
    severity_assessment: 'medium',
    severity_justification:
      'Theoretical risk of brute-forcing cryptographic tokens if network jitter allows timing extraction.',
    confidence_assessment: 'low',
    confidence_justification:
      'Unverified static heuristic alert; no dynamic evidence collected.',
    recommended_remediation:
      'Proactively update comparison functions to constant-time routines such as `crypto.timingSafeEqual()`.',
    limitations_and_missing_evidence: [
      'CRITICAL EVIDENCE GAP: Zero empirical timing measurements have been captured.',
      'AI analysis does NOT confirm this finding. It remains strictly UNVERIFIED pending verification probe.',
    ],
    cited_evidence_ids: [],
  },
  fnd_007: {
    finding_id: 'fnd_007',
    concise_summary:
      'False Positive: Path traversal probe was rejected by server router with HTTP 403 Forbidden.',
    reasoning_summary:
      'Evidence `ev_fp_005` confirms that path traversal sequence ..%2f was caught by static asset router, resulting in HTTP 403 without data exposure. Finding is classified as a FALSE POSITIVE.',
    severity_assessment: 'low',
    severity_justification:
      'Server defense mechanisms successfully neutralized traversal attempt.',
    confidence_assessment: 'high',
    confidence_justification:
      'Empirical HTTP 403 proof confirms defense in depth.',
    recommended_remediation:
      'No application patch required. Update scanner suppression list.',
    limitations_and_missing_evidence: [
      'Double encoding techniques (e.g. %252e%252e%252f) were not tested.',
    ],
    cited_evidence_ids: ['ev_fp_005'],
  },
};

export const DEMO_ACTIVITY_LOGS: ActivityEvent[] = [
  {
    id: 'act_001',
    assessment_id: 'asm_lab_001',
    timestamp: '2026-10-24T18:30:00Z',
    level: 'info',
    component: 'SCOPE_ENGINE',
    message: 'Assessment initialized. Target http://127.0.0.1:3000 verified in lab scope.',
  },
  {
    id: 'act_002',
    assessment_id: 'asm_lab_001',
    timestamp: '2026-10-24T18:31:00Z',
    level: 'info',
    component: 'OSINT_ADAPTER',
    message: 'Local asset discovery initiated. Identified port 3000 and 27017 active.',
  },
  {
    id: 'act_003',
    assessment_id: 'asm_lab_001',
    timestamp: '2026-10-24T18:34:00Z',
    level: 'info',
    component: 'SCANNER_WORKER',
    message: 'OWASP ZAP passive crawl complete. 35 endpoints identified.',
  },
  {
    id: 'act_004',
    assessment_id: 'asm_lab_001',
    timestamp: '2026-10-24T18:36:20Z',
    level: 'warning',
    component: 'SCANNER_WORKER',
    message: 'Potential SQL Injection anomaly flagged on /rest/products/search.',
  },
  {
    id: 'act_005',
    assessment_id: 'asm_lab_001',
    timestamp: '2026-10-24T18:37:05Z',
    level: 'success',
    component: 'AI_REASONER',
    message: 'Finding fnd_001 triaged and grounded in evidence ev_sql_001. Citation verified.',
  },
  {
    id: 'act_006',
    assessment_id: 'asm_lab_001',
    timestamp: '2026-10-24T18:38:15Z',
    level: 'warning',
    component: 'SCANNER_WORKER',
    message: 'BOLA vulnerability validated on /rest/basket/2 with secondary test account.',
  },
];
