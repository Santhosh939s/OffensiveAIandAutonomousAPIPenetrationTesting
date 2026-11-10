"""Unit tests for Finding Prioritization and Risk Assessment Engine."""

import unittest
from controller.reporting.risk_engine import (
    RiskAssessmentEngine,
    FindingRiskProfile,
    SessionRiskSummary,
    Severity,
)


class TestRiskAssessmentEngine(unittest.TestCase):
    """Test suite for CVSS v3.1 scoring, OWASP mapping, and session risk aggregation."""

    def test_sql_injection_confirmed_profile(self):
        """Confirm SQL Injection mapping to Critical severity and CWE-89."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="SQL Injection",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.CRITICAL)
        self.assertEqual(profile.cvss_score, 9.8)
        self.assertEqual(profile.cwe_id, "CWE-89")
        self.assertIn("parameterized queries", profile.remediation_guidance.lower())
        self.assertIn("API8:2023", profile.owasp_category)

        profile_dict = profile.to_dict()
        self.assertEqual(profile_dict["severity"], "CRITICAL")
        self.assertEqual(profile_dict["cwe_id"], "CWE-89")

    def test_bola_idor_confirmed_profile(self):
        """Confirm BOLA/IDOR mapping to High severity and CWE-639 / API1:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="BOLA / IDOR",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.HIGH)
        self.assertGreaterEqual(profile.cvss_score, 7.5)
        self.assertEqual(profile.cwe_id, "CWE-639")
        self.assertIn("API1:2023", profile.owasp_category)
        self.assertIn("owns", profile.remediation_guidance.lower())

    def test_broken_auth_jwt_none_profile(self):
        """Confirm Broken Authentication mapping to CWE-287 / API2:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="Broken Authentication (Insecure Algorithm)",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.HIGH)
        self.assertEqual(profile.cwe_id, "CWE-287")
        self.assertIn("API2:2023", profile.owasp_category)

    def test_mass_assignment_profile(self):
        """Confirm Mass Assignment mapping to CWE-915 / API3:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="Mass Assignment",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.HIGH)
        self.assertEqual(profile.cwe_id, "CWE-915")
        self.assertIn("API3:2023", profile.owasp_category)

    def test_graphql_introspection_profile(self):
        """Confirm GraphQL Introspection mapping to Low severity and CWE-16 / API8:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="GraphQL Introspection Enabled",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.LOW)
        self.assertEqual(profile.cvss_score, 5.3)
        self.assertEqual(profile.cwe_id, "CWE-16")
        self.assertIn("disable", profile.remediation_guidance.lower())

    def test_suspected_finding_score_discounting(self):
        """Verify that SUSPECTED findings receive a safety discount on score."""
        confirmed = RiskAssessmentEngine.get_finding_risk_profile(
            category="SQL Injection",
            status="CONFIRMED",
        )
        suspected = RiskAssessmentEngine.get_finding_risk_profile(
            category="SQL Injection",
            status="SUSPECTED",
        )
        self.assertLess(suspected.cvss_score, confirmed.cvss_score)
        self.assertEqual(suspected.cvss_score, round(confirmed.cvss_score * 0.8, 1))

    def test_untested_finding_demoted_to_informational(self):
        """Verify that UNTESTED or NOT_DEMONSTRATED findings are demoted to INFORMATIONAL."""
        untested = RiskAssessmentEngine.get_finding_risk_profile(
            category="SQL Injection",
            status="UNTESTED",
        )
        self.assertEqual(untested.severity, Severity.INFORMATIONAL)
        self.assertEqual(untested.cvss_score, 0.0)

    def test_session_risk_summary_empty(self):
        """Verify session summary handles empty findings cleanly."""
        summary = RiskAssessmentEngine.calculate_session_risk_summary([])
        self.assertEqual(summary.total_findings, 0)
        self.assertEqual(summary.confirmed_count, 0)
        self.assertEqual(summary.overall_risk_score, 0.0)
        self.assertEqual(summary.overall_risk_rating, Severity.INFORMATIONAL)

        s_dict = summary.to_dict()
        self.assertEqual(s_dict["total_findings"], 0)
        self.assertEqual(s_dict["overall_risk_score"], 0.0)

    def test_session_risk_summary_with_critical_finding(self):
        """Verify session summary correctly elevates to CRITICAL when critical flaw exists."""
        findings = [
            {"category": "SQL Injection", "status": "CONFIRMED", "evidence_notes": "syntax error"},
            {"category": "BOLA / IDOR", "status": "CONFIRMED", "evidence_notes": "cross-account leak"},
            {"category": "GraphQL Introspection Enabled", "status": "CONFIRMED", "evidence_notes": "__schema exposed"},
        ]
        summary = RiskAssessmentEngine.calculate_session_risk_summary(findings)
        self.assertEqual(summary.total_findings, 3)
        self.assertEqual(summary.confirmed_count, 3)
        self.assertEqual(summary.critical_count, 1)
        self.assertEqual(summary.high_count, 1)
        self.assertEqual(summary.low_count, 1)
        self.assertEqual(summary.overall_risk_rating, Severity.CRITICAL)
        self.assertGreaterEqual(summary.overall_risk_score, 9.0)
        self.assertEqual(len(summary.top_vulnerabilities), 3)
        # Verify ordering: Critical first
        self.assertEqual(summary.top_vulnerabilities[0]["category"], "SQL Injection")

    def test_bfla_risk_profile(self):
        """Confirm BFLA mapping to High severity and CWE-285 / API5:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="Broken Function Level Authorization (BFLA)",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.HIGH)
        self.assertEqual(profile.cvss_score, 8.5)
        self.assertEqual(profile.cwe_id, "CWE-285")
        self.assertIn("API5:2023", profile.owasp_category)
        self.assertIn("rbac", profile.remediation_guidance.lower())

    def test_business_flow_abuse_risk_profile(self):
        """Confirm Business Flow Abuse mapping to Medium severity and CWE-799 / API6:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="Unrestricted Access to Sensitive Business Flows",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.MEDIUM)
        self.assertEqual(profile.cvss_score, 6.5)
        self.assertEqual(profile.cwe_id, "CWE-799")
        self.assertIn("API6:2023", profile.owasp_category)
        self.assertIn("rate limiting", profile.remediation_guidance.lower())

    def test_shadow_api_inventory_risk_profile(self):
        """Confirm Shadow API mapping to Medium severity and CWE-1059 / API9:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="Improper Inventory Management (Shadow API)",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.MEDIUM)
        self.assertEqual(profile.cvss_score, 6.5)
        self.assertEqual(profile.cwe_id, "CWE-1059")
        self.assertIn("API9:2023", profile.owasp_category)

    def test_unsafe_api_consumption_risk_profile(self):
        """Confirm Unsafe API Consumption mapping to High severity and CWE-20 / API10:2023."""
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category="Unsafe Consumption of APIs",
            status="CONFIRMED",
        )
        self.assertEqual(profile.severity, Severity.HIGH)
        self.assertEqual(profile.cvss_score, 7.5)
        self.assertEqual(profile.cwe_id, "CWE-20")
        self.assertIn("API10:2023", profile.owasp_category)
        self.assertIn("schemas", profile.remediation_guidance.lower())


if __name__ == "__main__":
    unittest.main()
