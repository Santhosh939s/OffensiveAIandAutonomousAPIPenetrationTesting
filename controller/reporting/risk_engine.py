"""Risk Assessment and Finding Prioritization Engine.

Computes standard OWASP API Security Top 10 (2023) alignments, CWE identifiers,
CVSS v3.1 base metrics, severity levels, and actionable remediation guidance.
Provides deterministic risk scoring and finding prioritization for autonomous assessments.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Standard vulnerability severity ratings aligned with CVSS v3.1."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class FindingRiskProfile:
    """Standardized security risk profile for an individual finding."""
    category: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    remediation_guidance: str
    exploitability_rating: str = "Medium"
    technical_impact: str = "Potential degradation of application confidentiality, integrity, or availability."
    reproduction_steps: str = "Send safe verification request to target endpoint and inspect response headers and payload."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "remediation_guidance": self.remediation_guidance,
            "exploitability_rating": self.exploitability_rating,
            "technical_impact": self.technical_impact,
            "reproduction_steps": self.reproduction_steps,
        }


@dataclass
class SessionRiskSummary:
    """Aggregated risk scorecard for a penetration testing session."""
    total_findings: int
    confirmed_count: int
    suspected_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    overall_risk_score: float
    overall_risk_rating: Severity
    top_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "confirmed_count": self.confirmed_count,
            "suspected_count": self.suspected_count,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "overall_risk_score": round(self.overall_risk_score, 1),
            "overall_risk_rating": self.overall_risk_rating.value,
            "top_vulnerabilities": self.top_vulnerabilities,
        }


# Knowledge base of API vulnerability definitions
_VULNERABILITY_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "sql injection": {
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Use parameterized queries or prepared statements exclusively. Never interpolate user-supplied parameters directly into SQL queries.",
        "exploitability": "High",
    },
    "rce": {
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code ('Code Injection')",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Avoid passing user input to system shell execution functions. Implement strict command allowlists and sandboxing.",
        "exploitability": "High",
    },
    "bola / idor": {
        "severity": Severity.HIGH,
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key (BOLA / IDOR)",
        "owasp_category": "API1:2023 Broken Object Level Authorization (BOLA)",
        "remediation": "Validate that the authenticated requester owns or has explicit permission to access the requested resource object identifier on every endpoint invocation.",
        "exploitability": "High",
    },
    "broken object level authorization": {
        "severity": Severity.HIGH,
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "owasp_category": "API1:2023 Broken Object Level Authorization (BOLA)",
        "remediation": "Implement granular authorization checks at the data layer verifying requester tenant/user ownership.",
        "exploitability": "High",
    },
    "insecure authentication": {
        "severity": Severity.HIGH,
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "owasp_category": "API2:2023 Broken Authentication",
        "remediation": "Enforce strong authentication mechanisms, reject empty or default passwords, and require cryptographically signed tokens (e.g. RS256/ES256).",
        "exploitability": "High",
    },
    "insecure jwt": {
        "severity": Severity.HIGH,
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-347",
        "cwe_name": "Improper Verification of Cryptographic Signature",
        "owasp_category": "API2:2023 Broken Authentication",
        "remediation": "Reject JWT tokens specifying algorithm 'none'. Enforce strict signature verification using secure public/private keys.",
        "exploitability": "High",
    },
    "mass assignment": {
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe_id": "CWE-915",
        "cwe_name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "owasp_category": "API3:2023 Broken Object Property Level Authorization (BOPLA)",
        "remediation": "Define strict Data Transfer Object (DTO) schemas with field allowlists. Disallow automatic binding of sensitive fields like 'role' or 'is_admin'.",
        "exploitability": "Medium",
    },
    "bopla": {
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe_id": "CWE-915",
        "cwe_name": "Broken Object Property Level Authorization (BOPLA / Mass Assignment)",
        "owasp_category": "API3:2023 Broken Object Property Level Authorization (BOPLA)",
        "remediation": "Implement strict input schemas and read/write property-level permission controls.",
        "exploitability": "Medium",
    },
    "directory traversal": {
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Sanitize file path inputs using path canonicalization and reject directory traversal sequences (../). Restrict file operations to fixed root directories.",
        "exploitability": "High",
    },
    "ssrf": {
        "severity": Severity.HIGH,
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "owasp_category": "API7:2023 Server Side Request Forgery (SSRF)",
        "remediation": "Restrict outbound server network requests to explicit destination allowlists. Prohibit loopback (127.0.0.1) and cloud metadata addresses (169.254.169.254).",
        "exploitability": "Medium",
    },
    "xss": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Contextually encode all user-supplied output in HTML and JSON responses. Implement Content-Security-Policy (CSP) headers.",
        "exploitability": "Medium",
    },
    "graphql introspection enabled": {
        "severity": Severity.LOW,
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration / Information Exposure Through GraphQL Introspection",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Disable GraphQL schema introspection in production environments. Restrict query depth and query complexity.",
        "exploitability": "High",
    },
    "graphql introspection query enabled": {
        "severity": Severity.LOW,
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration / Information Exposure Through GraphQL Introspection",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Disable GraphQL schema introspection in production environments.",
        "exploitability": "High",
    },
    "unrestricted resource consumption": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe_id": "CWE-770",
        "cwe_name": "Allocation of Resources Without Limits or Throttling",
        "owasp_category": "API4:2023 Unrestricted Resource Consumption",
        "remediation": "Enforce strict rate limits, max page size limits, payload size ceilings, and execution timeouts on all API routes.",
        "exploitability": "Medium",
    },
    "broken function level authorization": {
        "severity": Severity.HIGH,
        "cvss_score": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-285",
        "cwe_name": "Improper Authorization (BFLA)",
        "owasp_category": "API5:2023 Broken Function Level Authorization (BFLA)",
        "remediation": "Enforce role-based access control (RBAC) or attribute-based access control (ABAC) on every administrative and sensitive endpoint.",
        "exploitability": "High",
    },
    "bfla": {
        "severity": Severity.HIGH,
        "cvss_score": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-285",
        "cwe_name": "Improper Authorization (BFLA)",
        "owasp_category": "API5:2023 Broken Function Level Authorization (BFLA)",
        "remediation": "Enforce role-based access control (RBAC) or attribute-based access control (ABAC) on every administrative and sensitive endpoint.",
        "exploitability": "High",
    },
    "unrestricted access to sensitive business flows": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe_id": "CWE-799",
        "cwe_name": "Improper Control of Interaction Frequency",
        "owasp_category": "API6:2023 Unrestricted Access to Sensitive Business Flows",
        "remediation": "Implement rate limiting, velocity checks, CAPTCHA, per-account quotas, and anti-automation controls on business flows.",
        "exploitability": "Medium",
    },
    "business flow abuse": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe_id": "CWE-799",
        "cwe_name": "Improper Control of Interaction Frequency (Business Flow Abuse)",
        "owasp_category": "API6:2023 Unrestricted Access to Sensitive Business Flows",
        "remediation": "Implement velocity limits, idempotency keys, single-use token constraints, and anti-automation protections on critical transactions.",
        "exploitability": "Medium",
    },
    "improper inventory management": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-1059",
        "cwe_name": "Incomplete Documentation / Improper Inventory Management",
        "owasp_category": "API9:2023 Improper Inventory Management",
        "remediation": "Decommission and retire outdated API versions, maintain an accurate central API catalog, and block external access to deprecated endpoints.",
        "exploitability": "High",
    },
    "shadow api": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-1059",
        "cwe_name": "Exposure of Undocumented / Shadow API Endpoint",
        "owasp_category": "API9:2023 Improper Inventory Management",
        "remediation": "Audit and decommission unadvertised or legacy shadow endpoints. Ensure all exposed APIs conform to current gateway routing policies.",
        "exploitability": "High",
    },
    "deprecated api": {
        "severity": Severity.MEDIUM,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-1059",
        "cwe_name": "Exposure of Deprecated API Version",
        "owasp_category": "API9:2023 Improper Inventory Management",
        "remediation": "Enforce API sunset schedules and disable routing to legacy API versions.",
        "exploitability": "High",
    },
    "unsafe consumption of apis": {
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation (Unsafe Consumption of Third-Party API Data)",
        "owasp_category": "API10:2023 Unsafe Consumption of APIs",
        "remediation": "Validate all incoming third-party and partner API payloads against strict schemas, verify digital signatures (HMAC), and validate downstream redirect URLs.",
        "exploitability": "Medium",
    },
    "unsafe api consumption": {
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation (Unsafe Downstream Consumption)",
        "owasp_category": "API10:2023 Unsafe Consumption of APIs",
        "remediation": "Validate all incoming third-party payloads against strict schemas and verify webhook signatures before processing.",
        "exploitability": "Medium",
    },
    "log4j": {
        "severity": Severity.CRITICAL,
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data (Log4j JNDI RCE)",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Upgrade Log4j libraries to patched releases and disable JNDI lookup mechanisms (log4j2.formatMsgNoLookups=true).",
        "exploitability": "High",
    },
    "log forging": {
        "severity": Severity.LOW,
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-117",
        "cwe_name": "Improper Output Handling for Logs",
        "owasp_category": "API8:2023 Security Misconfiguration",
        "remediation": "Sanitize all user-controlled data before writing to logs by stripping carriage return and newline characters.",
        "exploitability": "Low",
    },
    "cookie injection": {
        "severity": Severity.MEDIUM,
        "cvss_score": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-565",
        "cwe_name": "Reliance on Cookies without Validation and Integrity Checking",
        "owasp_category": "API2:2023 Broken Authentication",
        "remediation": "Store session state server-side and sign all cookies with HttpOnly, Secure, and SameSite attributes.",
        "exploitability": "Medium",
    },
}


_VULNERABILITY_IMPACTS: Dict[str, str] = {
    "sql injection": "Unauthorized access to database contents, exfiltration of sensitive records, data tampering, and potential underlying DBMS command execution.",
    "rce": "Arbitrary command execution within the application process context, leading to host compromise and lateral movement.",
    "bola / idor": "Unauthorized disclosure, modification, or deletion of other tenants' or users' records through manipulated object identifiers.",
    "broken object level authorization": "Unauthorized disclosure, modification, or deletion of other tenants' or users' records through manipulated object identifiers.",
    "insecure authentication": "Authentication bypass enabling unauthenticated adversaries to impersonate users and execute privileged operations.",
    "insecure jwt": "Cryptographic signature bypass enabling arbitrary token forging, privilege escalation, and full identity impersonation.",
    "mass assignment": "Privilege escalation and unauthorized data corruption via binding of internal object attributes (e.g., is_admin, role).",
    "bopla": "Privilege escalation and unauthorized data corruption via binding of internal object attributes (e.g., is_admin, role).",
    "directory traversal": "Unauthorized access to sensitive server filesystem resources, configuration files, and private credentials.",
    "ssrf": "Internal network scanning, access to loopback services, and potential exfiltration of cloud metadata credentials (169.254.169.254).",
    "xss": "Client-side code execution in victim browser sessions, session hijacking, credential theft, and DOM tampering.",
    "graphql introspection enabled": "Exposure of complete API data graph schema, queries, mutations, and field relationships facilitating targeted exploitation.",
    "graphql introspection query enabled": "Exposure of complete API data graph schema, queries, mutations, and field relationships facilitating targeted exploitation.",
    "unrestricted resource consumption": "Application exhaustion, denial-of-service, or database starvation through unbounded payload sizes or pagination abuse.",
    "broken function level authorization": "Administrative and privileged API functionality can be invoked by low-privileged or unauthenticated users.",
    "bfla": "Administrative and privileged API functionality can be invoked by low-privileged or unauthenticated users.",
    "unrestricted access to sensitive business flows": "Automated bot abuse of business-critical workflows (e.g. promo redemption, checkout, invitations) leading to financial or data loss.",
    "business flow abuse": "Automated bot abuse of business-critical workflows (e.g. promo redemption, checkout, invitations) leading to financial or data loss.",
    "improper inventory management": "Exposure of unmaintained, unpatched, or shadow API versions lacking modern security controls.",
    "shadow api": "Exposure of unmaintained, unpatched, or shadow API versions lacking modern security controls.",
    "deprecated api": "Exposure of unmaintained, unpatched, or shadow API versions lacking modern security controls.",
    "unsafe consumption of apis": "Injection, SSRF, or data corruption triggered downstream by processing unvalidated third-party API payloads.",
    "unsafe api consumption": "Injection, SSRF, or data corruption triggered downstream by processing unvalidated third-party API payloads.",
    "log4j": "Remote code execution via unescaped JNDI lookup strings evaluated by vulnerable Log4j libraries.",
    "log forging": "Log injection enabling forensic obfuscation, log splitting, and false audit trail generation.",
    "cookie injection": "Session hijacking or state manipulation via tampering with unverified client cookies.",
}

_VULNERABILITY_REPRODUCTIONS: Dict[str, str] = {
    "sql injection": "curl -s -X GET \"{endpoint}?id=1'\" -H \"Accept: application/json\" (Observe database syntax error disclosure in response body)",
    "rce": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"input\": \"; echo CANARY\"}'",
    "bola / idor": "curl -s -X GET \"{endpoint}\" -H \"Authorization: Bearer <UserA_Token>\" (Accessing User B's object identifier)",
    "broken object level authorization": "curl -s -X GET \"{endpoint}\" -H \"Authorization: Bearer <UserA_Token>\" (Accessing User B's object identifier)",
    "insecure authentication": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"username\": \"admin\", \"password\": \"\"}'",
    "insecure jwt": "curl -s -X GET \"{endpoint}\" -H \"Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.\"",
    "mass assignment": "curl -s -X PUT \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"role\": \"admin\", \"is_admin\": true}'",
    "bopla": "curl -s -X PUT \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"role\": \"admin\", \"is_admin\": true}'",
    "directory traversal": "curl -s -X GET \"{endpoint}?file=../../../../etc/passwd\"",
    "ssrf": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"url\": \"http://127.0.0.1:80/canary\"}'",
    "xss": "curl -s -X GET \"{endpoint}?q=<script>alert(1)</script>\"",
    "graphql introspection enabled": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"query\": \"{__schema{types{name}}}\"}'",
    "graphql introspection query enabled": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"query\": \"{__schema{types{name}}}\"}'",
    "unrestricted resource consumption": "curl -s -X GET \"{endpoint}?limit=100000\"",
    "broken function level authorization": "curl -s -X GET \"{endpoint}\" -H \"Authorization: Bearer <Unprivileged_Token>\"",
    "bfla": "curl -s -X GET \"{endpoint}\" -H \"Authorization: Bearer <Unprivileged_Token>\"",
    "unrestricted access to sensitive business flows": "for i in {1..5}; do curl -s -X POST \"{endpoint}\" -d '{\"promo\": \"DISCOUNT\"}'; done",
    "business flow abuse": "for i in {1..5}; do curl -s -X POST \"{endpoint}\" -d '{\"flow\": \"test\"}'; done",
    "improper inventory management": "curl -s -X GET \"{endpoint}\" (Probing unversioned or legacy /v1/ endpoints)",
    "shadow api": "curl -s -X GET \"{endpoint}\" (Probing unadvertised shadow route)",
    "deprecated api": "curl -s -X GET \"{endpoint}\" (Probing decommissioned API version)",
    "unsafe consumption of apis": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"partner_data\": \"<payload>\"}'",
    "unsafe api consumption": "curl -s -X POST \"{endpoint}\" -H \"Content-Type: application/json\" -d '{\"partner_data\": \"<payload>\"}'",
    "log4j": "curl -s -X GET \"{endpoint}?user=${jndi:ldap://127.0.0.1/canary}\"",
    "log forging": "curl -s -X GET \"{endpoint}?msg=test%0d%0aINJECTED_LOG_ENTRY\"",
    "cookie injection": "curl -s -X GET \"{endpoint}\" -H \"Cookie: session=tampered_value; role=admin\"",
}


def _find_best_match(target_text: str, candidates: Dict[str, Any]) -> Optional[Any]:
    """Match category name against candidate dictionary prioritizing exact and word-bounded matches."""
    target_clean = (target_text or "").lower().strip()
    # 1. Exact match
    if target_clean in candidates:
        return candidates[target_clean]

    # 2. Ordered by key length descending (longer, more specific multi-word keys first)
    sorted_keys = sorted(candidates.keys(), key=len, reverse=True)
    for key in sorted_keys:
        if len(key) <= 4:
            # Short acronyms (e.g. 'rce', 'xss', 'ssrf') require whole-word boundary
            if re.search(r"\b" + re.escape(key) + r"\b", target_clean):
                return candidates[key]
        else:
            if key in target_clean or target_clean in key:
                return candidates[key]
    return None


class RiskAssessmentEngine:
    """Computes finding-level risk metadata, prioritization, and session-level risk metrics."""

    @staticmethod
    def get_finding_risk_profile(
        category: str,
        status: str = "CONFIRMED",
        evidence_notes: str = "",
        endpoint: str = "/",
    ) -> FindingRiskProfile:
        """Resolve standardized risk metrics for an API security finding."""
        cat_lower = (category or "General Security Finding").lower().strip()
        matched_entry = _find_best_match(cat_lower, _VULNERABILITY_KNOWLEDGE_BASE)

        if matched_entry is None:
            # Fallback heuristics
            if any(term in cat_lower for term in ("injection", "rce", "overflow")):
                matched_entry = {
                    "severity": Severity.HIGH,
                    "cvss_score": 8.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cwe_id": "CWE-20",
                    "cwe_name": "Improper Input Validation",
                    "owasp_category": "API8:2023 Security Misconfiguration",
                    "remediation": "Validate, sanitize, and encode all external input.",
                    "exploitability": "Medium",
                }
            elif any(term in cat_lower for term in ("auth", "token", "jwt", "session", "credential")):
                matched_entry = {
                    "severity": Severity.HIGH,
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cwe_id": "CWE-287",
                    "cwe_name": "Improper Authentication",
                    "owasp_category": "API2:2023 Broken Authentication",
                    "remediation": "Strengthen authentication verification and token validation.",
                    "exploitability": "Medium",
                }
            elif any(term in cat_lower for term in ("idor", "bola", "access", "privilege", "role")):
                matched_entry = {
                    "severity": Severity.HIGH,
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    "cwe_id": "CWE-639",
                    "cwe_name": "Authorization Bypass",
                    "owasp_category": "API1:2023 Broken Object Level Authorization (BOLA)",
                    "remediation": "Implement strict object ownership authorization checks.",
                    "exploitability": "Medium",
                }
            elif any(term in cat_lower for term in ("leak", "disclosure", "header", "misconfig", "graphql")):
                matched_entry = {
                    "severity": Severity.MEDIUM,
                    "cvss_score": 5.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "cwe_id": "CWE-200",
                    "cwe_name": "Exposure of Sensitive Information",
                    "owasp_category": "API8:2023 Security Misconfiguration",
                    "remediation": "Harden server configuration and suppress internal debugging information.",
                    "exploitability": "Low",
                }
            else:
                matched_entry = {
                    "severity": Severity.INFORMATIONAL,
                    "cvss_score": 2.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "cwe_id": "CWE-699",
                    "cwe_name": "Software Development Vulnerability",
                    "owasp_category": "General Security Practice",
                    "remediation": "Review endpoint behavior and ensure compliance with security best practices.",
                    "exploitability": "Low",
                }

        # Demote effective severity if finding status is only SUSPECTED or UNTESTED
        status_norm = status.strip().upper()
        eff_severity = matched_entry["severity"]
        eff_score = matched_entry["cvss_score"]

        if status_norm == "SUSPECTED":
            # Suspected findings retain category details but score is slightly discounted
            eff_score = round(max(1.0, eff_score * 0.8), 1)
        elif status_norm in ("NOT_DEMONSTRATED", "UNTESTED"):
            eff_severity = Severity.INFORMATIONAL
            eff_score = 0.0

        # Technical Impact & Safe Reproduction Steps resolution
        impact = matched_entry.get("technical_impact")
        repro = matched_entry.get("reproduction_steps")

        if not impact:
            impact = _find_best_match(cat_lower, _VULNERABILITY_IMPACTS)
            if not impact:
                impact = "Potential compromise of endpoint confidentiality, integrity, or service availability."

        if not repro:
            repro = _find_best_match(cat_lower, _VULNERABILITY_REPRODUCTIONS)
            if not repro:
                repro = "Send safe HTTP verification request to target endpoint and evaluate response code and payload."

        repro_formatted = repro.replace("{endpoint}", endpoint or "/")

        return FindingRiskProfile(
            category=category,
            severity=eff_severity,
            cvss_score=eff_score,
            cvss_vector=matched_entry["cvss_vector"],
            cwe_id=matched_entry["cwe_id"],
            cwe_name=matched_entry["cwe_name"],
            owasp_category=matched_entry["owasp_category"],
            remediation_guidance=matched_entry["remediation"],
            exploitability_rating=matched_entry.get("exploitability", "Medium"),
            technical_impact=impact,
            reproduction_steps=repro_formatted,
        )

    @classmethod
    def calculate_session_risk_summary(cls, findings: List[Dict[str, Any]]) -> SessionRiskSummary:
        """Compute aggregated risk score and severity breakdown across all findings."""
        if not findings:
            return SessionRiskSummary(
                total_findings=0,
                confirmed_count=0,
                suspected_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                overall_risk_score=0.0,
                overall_risk_rating=Severity.INFORMATIONAL,
                top_vulnerabilities=[],
            )

        confirmed_count = sum(1 for f in findings if f.get("status") == "CONFIRMED")
        suspected_count = sum(1 for f in findings if f.get("status") == "SUSPECTED")

        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFORMATIONAL: 0,
        }

        enriched_findings: List[Dict[str, Any]] = []

        for f in findings:
            profile = cls.get_finding_risk_profile(
                category=f.get("category", "Unknown"),
                status=f.get("status", "UNTESTED"),
                evidence_notes=f.get("evidence_notes", ""),
            )
            counts[profile.severity] += 1
            f_copy = dict(f)
            f_copy.update(profile.to_dict())
            enriched_findings.append(f_copy)

        # Sort findings by severity and CVSS score descending
        severity_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFORMATIONAL: 1,
        }
        enriched_findings.sort(
            key=lambda item: (
                severity_order.get(Severity(item.get("severity", "INFORMATIONAL")), 0),
                item.get("cvss_score", 0.0),
                1 if item.get("status") == "CONFIRMED" else 0,
            ),
            reverse=True,
        )

        # Calculate overall weighted risk index (0.0 to 10.0)
        # Emphasizes confirmed critical/high vulnerabilities
        if confirmed_count == 0 and suspected_count == 0:
            overall_score = 0.0
            overall_rating = Severity.INFORMATIONAL
        else:
            base_score = 0.0
            if counts[Severity.CRITICAL] > 0:
                base_score = max(base_score, 9.0 + min(0.9, counts[Severity.CRITICAL] * 0.3))
                overall_rating = Severity.CRITICAL
            elif counts[Severity.HIGH] > 0:
                base_score = max(base_score, 7.0 + min(1.8, counts[Severity.HIGH] * 0.4))
                overall_rating = Severity.HIGH
            elif counts[Severity.MEDIUM] > 0:
                base_score = max(base_score, 4.0 + min(2.5, counts[Severity.MEDIUM] * 0.5))
                overall_rating = Severity.MEDIUM
            elif counts[Severity.LOW] > 0:
                base_score = max(base_score, 2.0 + min(1.8, counts[Severity.LOW] * 0.4))
                overall_rating = Severity.LOW
            else:
                base_score = 1.0
                overall_rating = Severity.INFORMATIONAL

            overall_score = min(10.0, base_score)

        return SessionRiskSummary(
            total_findings=len(findings),
            confirmed_count=confirmed_count,
            suspected_count=suspected_count,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFORMATIONAL],
            overall_risk_score=overall_score,
            overall_risk_rating=overall_rating,
            top_vulnerabilities=enriched_findings[:10],
        )

