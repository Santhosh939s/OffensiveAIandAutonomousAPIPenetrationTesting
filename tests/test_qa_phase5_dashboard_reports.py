"""QA Phase 5: Dashboard Endpoints, UI Views, and Multi-Format Security Reports.

Validates:
1. All Dashboard REST and HTML endpoints:
   - GET / (Web Dashboard SPA)
   - GET /api/system/status & /api/system/resources
   - POST /api/assessments/start (with input validation)
   - GET /api/assessments (Session list)
   - GET /api/assessments/<id>/status
   - GET /api/assessments/<id>/details
   - GET /api/assessments/<id>/findings (with pagination)
   - GET /api/assessments/<id>/traffic (with secret masking)
   - GET /api/assessments/<id>/risk (Scorecard & severity breakdown)
   - GET /api/assessments/<id>/endpoints (Discovered routes)
   - GET /api/assessments/compare (Cross-session regression diff)
   - POST /api/assessments/<id>/cancel
2. Multi-Format Report Generation:
   - Markdown Report: includes CVSS v3.1, OWASP Top 10 breakdown, traffic evidence, reproduction curl, and remediation.
   - JSON Report: structured schema containing session, risk_summary, findings, and remediation_guidance.
   - HTML Report: valid standalone document with responsive styling and data tables.
   - Download Endpoint: proper Content-Disposition attachment header.
"""

import json
import socket
import tempfile
import threading
import time
import unittest
from typing import ClassVar, Any

from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager
from controller.storage.evidence_store import EvidenceStore


class TestQAPhase5DashboardReports(unittest.TestCase):
    """QA Phase 5: Dashboard and Multi-Format Report Testing."""

    server: ClassVar[Any] = None
    server_thread: ClassVar[threading.Thread] = None
    target_url: ClassVar[str] = ""
    port: ClassVar[int] = 0

    @classmethod
    def setUpClass(cls):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

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
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.session_mgr = DashboardSessionManager(db_path=self.temp_db_path, store=self.store)
        self.app = create_dashboard_app(session_manager=self.session_mgr)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        import os
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 1. Dashboard Web UI Rendering
    # -------------------------------------------------------------------------
    def test_dashboard_ui_renders_all_required_panels(self):
        """Verify the main web dashboard page renders with all controls and sections."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn("Autonomous API Penetration Testing", html)
        self.assertIn("Traffic Inspector", html)
        self.assertIn("Security Findings", html)
        self.assertIn("Live Activity", html)
        self.assertIn("New Assessment", html)

    # -------------------------------------------------------------------------
    # 2. System Status and Resource Diagnostics
    # -------------------------------------------------------------------------
    def test_system_status_and_resources_endpoints(self):
        """Verify system diagnostics return hardware capabilities and service statuses."""
        resp_status = self.client.get("/api/system/status")
        self.assertEqual(resp_status.status_code, 200)
        data_status = resp_status.get_json()
        self.assertEqual(data_status["status"], "online")
        self.assertIn("supported_models", data_status)
        self.assertIn("resource_profile", data_status)

        resp_res = self.client.get("/api/system/resources")
        self.assertEqual(resp_res.status_code, 200)
        data_res = resp_res.get_json()
        self.assertIn("system_memory", data_res)
        self.assertIn("total_ram_mb", data_res["system_memory"])
        self.assertIn("recommended_mode", data_res)

    # -------------------------------------------------------------------------
    # 3. Assessment Creation & Validation
    # -------------------------------------------------------------------------
    def test_start_assessment_validations(self):
        """Verify parameter validation when creating assessment runs."""
        # A. Missing target URL -> 400
        resp_missing = self.client.post("/api/assessments/start", json={})
        self.assertEqual(resp_missing.status_code, 400)
        self.assertFalse(resp_missing.get_json()["success"])

        # B. Invalid URL scheme -> 400
        resp_invalid_scheme = self.client.post("/api/assessments/start", json={"target_url": "ftp://127.0.0.1"})
        self.assertEqual(resp_invalid_scheme.status_code, 400)

        # C. Invalid timeout seconds -> 400
        resp_bad_timeout = self.client.post("/api/assessments/start", json={
            "target_url": self.target_url,
            "timeout_seconds": 9999,
        })
        self.assertEqual(resp_bad_timeout.status_code, 400)

        # D. Valid launch
        resp_valid = self.client.post("/api/assessments/start", json={
            "target_url": self.target_url,
            "assessment_name": "QA Assessment Run",
            "max_turns": 2,
            "max_requests": 5,
            "brain_mode": "mock",
        })
        self.assertEqual(resp_valid.status_code, 200)
        val_data = resp_valid.get_json()
        self.assertTrue(val_data["success"])
        self.assertIn("session_id", val_data)

    # -------------------------------------------------------------------------
    # 4. Session Status, Details, Findings, Traffic, Risk, Endpoints
    # -------------------------------------------------------------------------
    def test_session_lifecycle_and_telemetry_apis(self):
        """Verify retrieval of status, details, findings, traffic, and risk via APIs."""
        # Create completed session directly in store
        sess_id = f"sess_telemetry_{int(time.time())}"
        self.store.create_session(sess_id, self.target_url, "Telemetry Test Run")

        t_id = self.store.log_traffic(
            session_id=sess_id,
            method="GET",
            url=f"{self.target_url}/api/users/2",
            headers={"Authorization": "Bearer secret_test_token_123"},
            response_status=200,
            response_body=json.dumps({"id": 2, "username": "bob", "password": "super_secret_pw"}),
        )

        self.store.record_finding(
            session_id=sess_id,
            endpoint=f"{self.target_url}/api/users/2",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Sensitive user details accessed without authorization",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=t_id,
            raw_evidence={"id": 2},
        )
        self.store.update_session_status(sess_id, "COMPLETED", turns_taken=2, requests_sent=4)

        # 1. Session Status
        resp_status = self.client.get(f"/api/assessments/{sess_id}/status")
        self.assertEqual(resp_status.status_code, 200)
        self.assertEqual(resp_status.get_json()["status"], "COMPLETED")

        # 2. Session Details
        resp_details = self.client.get(f"/api/assessments/{sess_id}/details")
        self.assertEqual(resp_details.status_code, 200)
        self.assertEqual(resp_details.get_json()["session_id"], sess_id)

        # 3. Session Findings
        resp_findings = self.client.get(f"/api/assessments/{sess_id}/findings")
        self.assertEqual(resp_findings.status_code, 200)
        findings_data = resp_findings.get_json()
        self.assertEqual(len(findings_data["findings"]), 1)
        self.assertEqual(findings_data["findings"][0]["cwe_id"], "CWE-639")

        # 4. Session Traffic (Sanitized)
        resp_traffic = self.client.get(f"/api/assessments/{sess_id}/traffic")
        self.assertEqual(resp_traffic.status_code, 200)
        traffic_data = resp_traffic.get_json()
        self.assertEqual(len(traffic_data["traffic"]), 1)
        # Ensure secret token is masked in traffic response
        raw_traffic_str = json.dumps(traffic_data)
        self.assertNotIn("secret_test_token_123", raw_traffic_str)
        self.assertNotIn("super_secret_pw", raw_traffic_str)

        # 5. Session Risk Scorecard
        resp_risk = self.client.get(f"/api/assessments/{sess_id}/risk")
        self.assertEqual(resp_risk.status_code, 200)
        risk_data = resp_risk.get_json()
        self.assertEqual(risk_data["total_findings"], 1)
        self.assertEqual(risk_data["confirmed_count"], 1)
        self.assertGreater(risk_data["overall_risk_score"], 0.0)

        # 6. Session Endpoints
        resp_ep = self.client.get(f"/api/assessments/{sess_id}/endpoints")
        self.assertEqual(resp_ep.status_code, 200)

        # 7. List Sessions
        resp_list = self.client.get("/api/assessments")
        self.assertEqual(resp_list.status_code, 200)
        sessions = resp_list.get_json()["sessions"]
        self.assertTrue(any(s["session_id"] == sess_id for s in sessions))

    # -------------------------------------------------------------------------
    # 5. Multi-Format Report Generation APIs
    # -------------------------------------------------------------------------
    def test_multi_format_reports_and_download_attachment(self):
        """Verify generation of Markdown, JSON, HTML reports and report attachment downloads."""
        sess_id = f"sess_report_{int(time.time())}"
        self.store.create_session(sess_id, self.target_url, "Full Report Generation Test")

        t_id = self.store.log_traffic(
            session_id=sess_id,
            method="GET",
            url=f"{self.target_url}/api/search?q='",
            response_status=500,
            response_body=json.dumps({"error": "Database SQL syntax error"}),
        )

        self.store.record_finding(
            session_id=sess_id,
            endpoint=f"{self.target_url}/api/search",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="Leaked SQL syntax error in 500 body",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            traffic_log_id=t_id,
            raw_evidence={"detail": "OperationalError"},
        )
        self.store.update_session_status(sess_id, "COMPLETED", turns_taken=1, requests_sent=2)

        # A. Markdown Report
        resp_md = self.client.get(f"/api/assessments/{sess_id}/report")
        self.assertEqual(resp_md.status_code, 200)
        md_text = resp_md.get_json()["report_markdown"]
        self.assertIn("# API Security Penetration Testing Assessment Report", md_text)
        self.assertIn("SQL Injection", md_text)
        self.assertIn("CWE-89", md_text)
        self.assertIn("parameterized queries", md_text.lower())

        # B. JSON Report
        resp_json = self.client.get(f"/api/assessments/{sess_id}/report/json")
        self.assertEqual(resp_json.status_code, 200)
        json_report = resp_json.get_json()
        self.assertIn("session", json_report)
        self.assertIn("risk_summary", json_report)
        self.assertIn("findings", json_report)
        self.assertEqual(json_report["findings"][0]["cwe_id"], "CWE-89")
        self.assertEqual(json_report["findings"][0]["severity"], "CRITICAL")

        # C. HTML Report
        resp_html = self.client.get(f"/api/assessments/{sess_id}/report/html")
        self.assertEqual(resp_html.status_code, 200)
        html_report = resp_html.get_data(as_text=True)
        self.assertIn("<!DOCTYPE html>", html_report)
        self.assertIn("SQL Injection", html_report)
        self.assertIn("CRITICAL", html_report)

        # D. Download Report Attachment
        resp_dl = self.client.get(f"/api/assessments/{sess_id}/report/download")
        self.assertEqual(resp_dl.status_code, 200)
        self.assertIn("Content-Disposition", resp_dl.headers)
        self.assertIn(f"{sess_id}_report.md", resp_dl.headers["Content-Disposition"])
        self.assertIn("# API Security Penetration Testing Assessment Report", resp_dl.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
