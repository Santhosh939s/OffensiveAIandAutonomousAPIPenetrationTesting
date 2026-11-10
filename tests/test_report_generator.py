"""Unit tests for Multi-Format Security Report Generator (Markdown, JSON, HTML)."""

import json
import unittest
from controller.reporting.report_generator import ReportGenerator
from controller.storage.evidence_store import EvidenceStore


class TestReportGenerator(unittest.TestCase):
    """Test suite for Markdown, JSON, and HTML report formatting and output integrity."""

    def setUp(self):
        self.store = EvidenceStore(":memory:")
        self.session_id = "test_sess_rep_001"
        self.store.create_session(
            session_id=self.session_id,
            target="http://127.0.0.1:5000",
            notes="Comprehensive Multi-Format Test Assessment",
        )

    def tearDown(self):
        if self.store._shared_conn:
            self.store._shared_conn.close()

    def test_empty_session_reports(self):
        """Verify report generation handles sessions with no findings gracefully."""
        self.store.update_session_status(
            session_id=self.session_id,
            status="COMPLETED",
            turns_taken=1,
            requests_sent=1,
            notes="Testing clean endpoints",
        )
        reporter = ReportGenerator(self.store)

        # 1. Markdown
        md = reporter.generate_report(self.session_id)
        self.assertIn("# API Security Penetration Testing Assessment Report", md)
        self.assertIn(self.session_id, md)
        self.assertTrue("Clean" in md or "None identified" in md)

        # 2. JSON
        data = reporter.generate_json_report(self.session_id)
        self.assertEqual(data["report_version"], "2.0.0")
        self.assertEqual(data["session"]["session_id"], self.session_id)
        self.assertEqual(data["risk_summary"]["total_findings"], 0)
        self.assertEqual(data["findings"], [])

        # 3. HTML
        html = reporter.generate_html_report(self.session_id)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn(self.session_id, html)
        self.assertIn("API Security Assessment Report", html)

    def test_populated_session_multi_format_reports(self):
        """Verify report outputs accurately render findings, risk metrics, and remediations."""
        # 1. Ingest specification
        self.store.record_specification(
            session_id=self.session_id,
            spec_source="http://127.0.0.1:5000/openapi.json",
            title="Vulnerable Test API",
            spec_version="1.0.0",
            endpoints_count=3,
            spec_data={"paths": {"/api/search": {}, "/api/orders": {}, "/graphql": {}}},
        )

        # 2. Record findings
        self.store.record_finding(
            session_id=self.session_id,
            endpoint="http://127.0.0.1:5000/api/search",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="Database syntax error confirmed via quote probe.",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            raw_evidence={"syntax_error": True, "status_code": 500},
        )
        self.store.record_finding(
            session_id=self.session_id,
            endpoint="http://127.0.0.1:5000/api/orders/102",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Cross-account customer order data leaked without authorization.",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            raw_evidence={"customer": "Bob", "status_code": 200},
        )
        self.store.record_finding(
            session_id=self.session_id,
            endpoint="http://127.0.0.1:5000/graphql",
            category="GraphQL Introspection Enabled",
            status="CONFIRMED",
            evidence_notes="GraphQL schema introspection query executed successfully.",
            verification_rule="GRAPHQL_INTROSPECTION_EXPOSED",
            raw_evidence={"types_count": 8, "status_code": 200},
        )

        # 3. Log traffic
        self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url="http://127.0.0.1:5000/api/search?q='",
            headers={"Accept": "application/json"},
            request_body="",
            response_status=500,
            response_headers={"Content-Type": "text/plain"},
            response_body="SQL syntax error near quote",
            elapsed_ms=12.4,
        )

        # 4. Log tool execution
        self.store.log_tool_execution(
            session_id=self.session_id,
            tool_name="httpx_request",
            approved=True,
            policy_reason="Authorized localhost target",
            arguments={"url": "http://127.0.0.1:5000/api/search?q='"},
            duration_ms=15.2,
        )

        self.store.update_session_status(
            session_id=self.session_id,
            status="COMPLETED",
            turns_taken=3,
            requests_sent=3,
            notes="Testing complete with 3 confirmed vulnerabilities",
        )

        reporter = ReportGenerator(self.store)

        # Test Markdown Report
        md = reporter.generate_report(self.session_id)
        self.assertIn("SQL Injection", md)
        self.assertIn("BOLA / IDOR", md)
        self.assertIn("GraphQL Introspection Enabled", md)
        self.assertIn("CWE-89", md)
        self.assertIn("CWE-639", md)
        self.assertIn("CWE-16", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("Scope & Authorization Verification", md)
        self.assertIn("Tool Activity & Execution Audit Trail", md)

        # Test JSON Report
        json_data = reporter.generate_json_report(self.session_id)
        self.assertEqual(len(json_data["findings"]), 3)
        self.assertEqual(json_data["risk_summary"]["total_findings"], 3)
        self.assertEqual(json_data["risk_summary"]["confirmed_count"], 3)
        self.assertEqual(json_data["risk_summary"]["severity_counts"]["critical"], 1)
        self.assertEqual(json_data["risk_summary"]["severity_counts"]["high"], 1)
        self.assertEqual(json_data["risk_summary"]["overall_risk_rating"], "CRITICAL")
        self.assertEqual(len(json_data["tool_executions"]), 1)
        self.assertEqual(len(json_data["traffic_sample"]), 1)
        self.assertEqual(json_data["total_traffic_count"], 1)
        self.assertEqual(len(json_data["specifications"]), 1)

        # Test HTML Report
        html = reporter.generate_html_report(self.session_id)
        self.assertIn("badge-critical", html)
        self.assertIn("CWE-89", html)
        self.assertIn("CWE-639", html)
        self.assertIn("SQL Injection", html)
        self.assertIn("BOLA / IDOR", html)
        self.assertIn("Overall Risk Score", html)
        self.assertIn("Remediation", html)

    def test_invalid_session_handling(self):
        """Verify graceful error messages when non-existent session ID is requested."""
        reporter = ReportGenerator(self.store)
        md = reporter.generate_report("nonexistent_session")
        self.assertIn("Report Generation Error", md)

        json_data = reporter.generate_json_report("nonexistent_session")
        self.assertIn("error", json_data)

        html = reporter.generate_html_report("nonexistent_session")
        self.assertIn("Error", html)
        self.assertIn("nonexistent_session", html)


if __name__ == "__main__":
    unittest.main()
