"""End-to-End Integration Test: Autonomous Controller Assessment of Local Vulnerable API Lab.

Tests the full closed-loop autonomous penetration testing pipeline:
1. Starts the authentic Local Vulnerable API Lab server (REST + GraphQL endpoints) on 127.0.0.1.
2. Ingests the API schema via OpenAPI / Swagger parser.
3. Probes the GraphQL endpoint for schema introspection misconfiguration.
4. Performs guided security probing across endpoints (BOLA/IDOR, SQL Syntax Error).
5. Validates findings through Evidence Verification Gates (confirming genuine flaws, auto-demoting anomalies).
6. Generates full Markdown and HTML security assessment reports.
"""

import json
import socket
import threading
import time
import unittest
from typing import ClassVar, Any

from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.storage.evidence_store import EvidenceStore
from controller.reporting.report_generator import ReportGenerator
from controller.tools import build_default_tool_registry


class TestLabEndToEndAssessment(unittest.TestCase):
    """End-to-end integration test verifying the entire pentesting stack against a real target."""

    server: ClassVar[Any] = None
    server_thread: ClassVar[threading.Thread] = None
    target_url: ClassVar[str] = ""
    port: ClassVar[int] = 0

    @classmethod
    def setUpClass(cls):
        # 1. Allocate free port on localhost
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        # 2. Start authentic Local API Lab
        db = LabDatabase(":memory:")
        app = create_app(db)
        cls.server = make_server("127.0.0.1", cls.port, app)
        cls.target_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()

    def setUp(self):
        self.config = AgentConfig(
            max_turns=25,
            max_requests_per_session=70,
            zap_active_scan_enabled=False,
        )
        self.store = EvidenceStore(db_path=":memory:")
        self.brain = DeterministicMockBrainClient()
        self.tools = build_default_tool_registry()
        self.controller = AutonomousController(
            config=self.config,
            model_brain=self.brain,
            evidence_store=self.store,
            tool_registry=self.tools,
        )

    def test_e2e_assessment_lifecycle_with_real_api_lab(self):
        """Execute full end-to-end assessment against the authentic Local API Security Lab."""
        # 1. Run closed-loop autonomous assessment with OpenAPI discovery
        result = self.controller.run_assessment(
            target_url=self.target_url,
            spec_source=f"{self.target_url}/openapi.json",
            session_notes="Automated E2E Lab Assessment",
        )

        self.assertTrue(result["success"])
        session_id = result["session_id"]
        self.assertIsNotNone(session_id)
        self.assertGreater(result["requests_sent"], 0)
        self.assertGreater(result["turns_taken"], 0)

        # 2. Verify autonomously discovered and confirmed security findings
        findings = self.store.get_findings(session_id)
        self.assertGreaterEqual(len(findings), 8)

        categories = {f["category"] for f in findings}
        rules = {f["verification_rule"] for f in findings}
        statuses = {f["status"] for f in findings}

        self.assertIn("CONFIRMED", statuses)
        self.assertIn("SQL_SYNTAX_ERROR_MATCH", rules)
        self.assertIn("BFLA_ADMIN_FUNCTION_BYPASS", rules)
        self.assertIn("BUSINESS_FLOW_UNRESTRICTED_ACCESS", rules)
        self.assertIn("UNSAFE_DOWNSTREAM_API_CONSUMPTION", rules)
        self.assertIn("TOKEN_ALGORITHM_NONE_ACCEPTED", rules)
        self.assertIn("ROLE_ELEVATION_VERIFIED", rules)
        self.assertTrue(any("BOLA" in c for c in categories))
        self.assertTrue(any("GraphQL" in c for c in categories))

        # Check confirmed findings have CVSS, CWE, and remediation enriched
        confirmed_findings = [f for f in findings if f["status"] == "CONFIRMED"]
        for cf in confirmed_findings:
            self.assertGreater(cf["cvss_score"], 0.0)
            self.assertTrue(cf["cwe_id"].startswith("CWE-"))
            self.assertGreater(len(cf["remediation"]), 5)

        # 3. Direct Inventory Scanner tool verification (API9:2023 Improper Inventory)
        inv_tool = self.tools.get("inventory_scanner")
        self.assertIsNotNone(inv_tool)
        inv_res = inv_tool.execute(
            target_url=self.target_url,
            candidate_paths=["/api/v1/users/export", "/api/v1/debug/dump"],
            known_endpoints=["/api/users", "/api/orders"],
        )
        self.assertTrue(inv_res["success"])
        self.assertGreaterEqual(inv_res["shadow_count"], 2)
        self.assertGreaterEqual(len(inv_res["findings"]), 2)

        # Record inventory finding to store
        inv_fid, inv_status = self.store.record_finding(
            session_id=session_id,
            endpoint=f"{self.target_url}/api/v1/users/export",
            category="Improper Inventory Management (Shadow API)",
            status="CONFIRMED",
            evidence_notes="Unadvertised legacy v1 API endpoint exposed sensitive user tokens.",
            verification_rule="SHADOW_OR_DEPRECATED_API_EXPOSED",
            raw_evidence={"shadow_api": True, "status_code": 200},
        )
        self.assertEqual(inv_status, "CONFIRMED")

        # 4. Direct GraphQL probe tool verification against lab target
        graphql_tool = self.tools.get("graphql_probe")
        self.assertIsNotNone(graphql_tool)
        gql_res = graphql_tool.execute(target_url=f"{self.target_url}/graphql")
        self.assertTrue(gql_res["success"])
        self.assertEqual(len(gql_res["discovered_endpoints"]), 1)
        self.assertGreater(len(gql_res["findings"]), 0)
        self.assertEqual(gql_res["findings"][0]["type"], "GRAPHQL_INTROSPECTION_ENABLED")

        # 4. Generate Multi-Format Security Reports (Markdown, JSON, HTML)
        reporter = ReportGenerator(self.store)

        # 4a. Markdown Report
        report_md = reporter.generate_report(session_id)
        self.assertIn("# API Security Penetration Testing Assessment Report", report_md)
        self.assertIn(self.target_url, report_md)
        self.assertIn("Scope & Authorization Verification", report_md)
        self.assertIn("Executive Risk Summary", report_md)
        self.assertIn("SQL Injection", report_md)

        # 4b. JSON Report
        report_json = reporter.generate_json_report(session_id)
        self.assertEqual(report_json["report_version"], "2.0.0")
        self.assertEqual(report_json["session"]["session_id"], session_id)
        self.assertGreaterEqual(report_json["risk_summary"]["total_findings"], 4)
        self.assertIn(report_json["risk_summary"]["overall_risk_rating"], ["CRITICAL", "HIGH"])
        self.assertGreater(len(report_json["traffic_sample"]), 0)

        # 4c. HTML Report
        report_html = reporter.generate_html_report(session_id)
        self.assertIn("<!DOCTYPE html>", report_html)
        self.assertIn("API Security Assessment Report", report_html)
        self.assertIn("badge-critical", report_html)
        self.assertIn("Overall Risk Score", report_html)


if __name__ == "__main__":
    unittest.main()
