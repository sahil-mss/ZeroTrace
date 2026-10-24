# Permanent Project Security and Engineering Rules — AegisPT

These rules apply to all automated agents, developers, and integrated modules across the AegisPT project. They are permanent, binding, and must be strictly followed at all times.

## 1. Scope, Authorization & Policy Rules
- **Explicit Authorization Only**: Assessments must only be performed against explicitly authorized assets and approved lab environments (e.g., local OWASP Juice Shop).
- **Default Deny**: Default to denying actions whenever authorization, scope parameters, or permissions are missing or ambiguous.
- **No Inferred Scope**: Never treat a subdomain, IP address, or redirect destination as authorized merely because it was discovered during reconnaissance.
- **Pre-execution Revalidation**: Always revalidate any destination against the assessment's approved scope policy before invoking any tool or scan.
- **Deterministic Policy Enforcement**: Keep scope and permission policy enforcement deterministic, auditable, and completely independent of AI model decisions.

## 2. Model & Execution Boundaries
- **No Unrestricted Execution**: Never give an AI model unrestricted shell, filesystem, or network execution capabilities.
- **No Arbitrary Commands**: Never construct or execute arbitrary shell commands from model output or user-supplied strings. Use predefined, validated tool profiles and argument lists.
- **No Automatic Scans in Development**: Do not run scans or trigger external network requests automatically during development, startup, or testing.

## 3. Resiliency, Rate Limits & Provenance
- **Bounded External Adapters**: All external-source adapters (OSINT, DNS, APIs) must enforce strict timeouts, bounded response sizes, and rate limits.
- **Job Controls**: All jobs must support resource limits, timeouts, clean cancellation, and immutable audit event logging.
- **Evidence Integrity & Truthfulness**: Never fabricate scan results, evidence records, vulnerability confirmations, or test results. Every finding must trace back to verifiable evidence.
- **Zero Sensitive Commits**: Never commit API keys, passwords, credentials, private datasets, or sensitive scan artifacts.

## 4. Engineering & Testing Standards
- **Deterministic Offline Testing**: Tests must use synthetic data, mocks, or controlled local fixtures and must not require live internet access.
- **Verification of Pass/Fail**: Never claim a test passed unless you actually ran it and observed the result.
- **Reviewable Increments**: Preserve existing working code and make small, cohesive, reviewable changes.
- **Documented Changes**: Clearly explain all dependencies and security-sensitive changes before implementation.
