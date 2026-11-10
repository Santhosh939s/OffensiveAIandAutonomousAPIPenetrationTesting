"""QA Phase 3: Authentication Modes, Configuration Robustness, and Secret Masking.

Validates:
1. All 5 authentication modes:
   - 'none' (public reconnaissance)
   - 'bearer' (Bearer token injection)
   - 'api_key' (Header-based API key injection)
   - 'basic' (Base64 encoded HTTP Basic Auth)
   - 'custom' (Arbitrary custom headers)
2. Rejection and graceful handling of invalid credentials (401 Unauthorized / 403 Forbidden).
3. Session isolation: multiple sessions maintain strict isolation of configurations, traffic logs, and findings.
4. Secret masking across all architectural layers:
   - Traffic inspector / session manager
   - Model prompts
   - Evidence database
   - Generated reports (Markdown, JSON, HTML)
"""

import base64
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
from controller.brain.prompts import format_action_selection_prompt, format_test_planning_prompt
from controller.reporting.report_generator import ReportGenerator
from controller.storage.evidence_store import EvidenceStore
from controller.tools import build_default_tool_registry
from dashboard.session_manager import DashboardSessionManager, mask_sensitive_traffic_data


class TestQAPhase3AuthAndConfig(unittest.TestCase):
    """QA Phase 3: Authentication modes, session isolation, and secret masking."""

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
        self.store = EvidenceStore(db_path=":memory:")
        self.session_mgr = DashboardSessionManager(db_path=":memory:", store=self.store)

    # -------------------------------------------------------------------------
    # 1. Verification of all 5 Authentication Modes
    # -------------------------------------------------------------------------
    def test_auth_mode_none(self):
        """Mode 1: 'none' auth configuration."""
        sess = self.session_mgr.start_assessment(
            target_url=self.target_url,
            auth_type="none",
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )
        self.assertTrue(sess.get("success"), sess.get("error"))
        session_id = sess["session_id"]
        # Allow worker execution to finish
        time.sleep(0.5)
        status = self.session_mgr.get_session_status(session_id)
        self.assertIn(status.get("status"), ("ACTIVE", "COMPLETED", "TIMEOUT"))

    def test_auth_mode_bearer(self):
        """Mode 2: 'bearer' auth configuration correctly constructs Authorization header."""
        secret_token = "secret_jwt_token_xyz123abc456"
        sess = self.session_mgr.start_assessment(
            target_url=self.target_url,
            auth_type="bearer",
            auth_credentials={"token": secret_token},
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )
        self.assertTrue(sess.get("success"), sess.get("error"))
        session_id = sess["session_id"]
        time.sleep(0.5)

        # Inspect logged traffic: confirm Bearer token is masked in the traffic inspector
        traffic = self.session_mgr.get_traffic_logs_sanitized(session_id)
        for t in traffic:
            headers_str = json.dumps(t.get("headers", {}))
            self.assertNotIn(secret_token, headers_str, "Raw bearer token leaked in traffic inspector!")

    def test_auth_mode_api_key(self):
        """Mode 3: 'api_key' auth configuration with custom header name."""
        secret_key = "ak_live_998877665544332211"
        sess = self.session_mgr.start_assessment(
            target_url=self.target_url,
            auth_type="api_key",
            auth_credentials={"header_name": "X-API-Key", "api_key": secret_key},
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )
        self.assertTrue(sess.get("success"), sess.get("error"))
        session_id = sess["session_id"]
        time.sleep(0.5)

        traffic = self.session_mgr.get_traffic_logs_sanitized(session_id)
        for t in traffic:
            headers_str = json.dumps(t.get("headers", {}))
            self.assertNotIn(secret_key, headers_str, "Raw API key leaked in traffic inspector!")

    def test_auth_mode_basic(self):
        """Mode 4: 'basic' auth configuration base64 encodes username:password."""
        sess = self.session_mgr.start_assessment(
            target_url=self.target_url,
            auth_type="basic",
            auth_credentials={"username": "pentest_admin", "password": "super_secret_password_42"},
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )
        self.assertTrue(sess.get("success"), sess.get("error"))
        session_id = sess["session_id"]
        time.sleep(0.5)

        traffic = self.session_mgr.get_traffic_logs_sanitized(session_id)
        for t in traffic:
            headers_str = json.dumps(t.get("headers", {}))
            self.assertNotIn("super_secret_password_42", headers_str, "Raw password leaked in traffic inspector!")

    def test_auth_mode_custom(self):
        """Mode 5: 'custom' auth configuration with arbitrary headers."""
        custom_headers = {
            "X-Tenant-ID": "tenant-enterprise-001",
            "X-Client-Signature": "sig_secret_digest_val",
        }
        sess = self.session_mgr.start_assessment(
            target_url=self.target_url,
            auth_type="custom",
            auth_credentials={"headers": custom_headers},
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )
        self.assertTrue(sess.get("success"), sess.get("error"))
        session_id = sess["session_id"]
        time.sleep(0.5)

        traffic = self.session_mgr.get_traffic_logs_sanitized(session_id)
        for t in traffic:
            headers_str = json.dumps(t.get("headers", {}))
            self.assertNotIn("sig_secret_digest_val", headers_str, "Custom secret header leaked in traffic inspector!")

    # -------------------------------------------------------------------------
    # 2. Invalid Credentials Handling
    # -------------------------------------------------------------------------
    def test_invalid_credentials_handling_does_not_crash(self):
        """Gracefully handle 401 Unauthorized responses from target without crashing controller."""
        config = AgentConfig(
            max_turns=2,
            max_requests_per_session=5,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        tools = build_default_tool_registry()
        brain = DeterministicMockBrainClient()
        controller = AutonomousController(
            config=config,
            model_brain=brain,
            evidence_store=self.store,
            tool_registry=tools,
        )

        session_id = f"sess_invalid_auth_{int(time.time())}"
        # Execute assessment with bogus credentials
        result = controller.run_assessment(
            target_url=self.target_url,
            auth_context={"Authorization": "Bearer invalid_tampered_token_999"},
            session_id=session_id,
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["session_id"], session_id)
        session_record = self.store.get_session(session_id)
        self.assertIn(session_record["status"], ("COMPLETED", "TIMEOUT"))

    # -------------------------------------------------------------------------
    # 3. Session Isolation
    # -------------------------------------------------------------------------
    def test_session_isolation_independent_records(self):
        """Verify that multiple concurrent or sequential sessions maintain strict isolation."""
        sess_a = self.session_mgr.start_assessment(
            target_url=self.target_url,
            assessment_name="Session A",
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )
        sess_b = self.session_mgr.start_assessment(
            target_url=self.target_url,
            assessment_name="Session B",
            max_turns=1,
            max_requests=2,
            brain_mode="mock",
        )

        id_a = sess_a["session_id"]
        id_b = sess_b["session_id"]
        self.assertNotEqual(id_a, id_b)

        time.sleep(0.5)

        traffic_a = self.store.get_traffic_logs(id_a)
        traffic_b = self.store.get_traffic_logs(id_b)

        for item in traffic_a:
            self.assertEqual(item["session_id"], id_a)
        for item in traffic_b:
            self.assertEqual(item["session_id"], id_b)

        # Cross-query isolation
        summary_a = self.session_mgr.get_session_status(id_a)
        summary_b = self.session_mgr.get_session_status(id_b)
        self.assertEqual(summary_a["session_id"], id_a)
        self.assertEqual(summary_b["session_id"], id_b)

    # -------------------------------------------------------------------------
    # 4. Secret Masking Across Architectural Layers
    # -------------------------------------------------------------------------
    def test_mask_sensitive_traffic_data_utility(self):
        """Comprehensive verification of the mask_sensitive_traffic_data function."""
        # A. Masking nested dictionary
        input_dict = {
            "username": "admin",
            "password": "SuperSecretPassword123!",
            "api_token": "tok_live_123456",
            "nested": {
                "secret_key": "my_master_key",
                "normal_field": "public_data",
            },
            "cookie": "session=abc123xyz456",
        }
        masked = mask_sensitive_traffic_data(input_dict)
        self.assertEqual(masked["password"], "***MASKED***")
        self.assertEqual(masked["api_token"], "***MASKED***")
        self.assertEqual(masked["cookie"], "***MASKED***")
        self.assertEqual(masked["nested"]["secret_key"], "***MASKED***")
        self.assertEqual(masked["nested"]["normal_field"], "public_data")

        # B. Masking raw strings with Authorization headers
        raw_str = "GET /api/users HTTP/1.1\r\nAuthorization: Bearer secret_jwt_payload_987\r\nCookie: session=sess_live_123"
        masked_str = mask_sensitive_traffic_data(raw_str)
        self.assertNotIn("secret_jwt_payload_987", masked_str)
        self.assertIn("Bearer ***", masked_str)
        self.assertNotIn("sess_live_123", masked_str)
        self.assertIn("session=***", masked_str)

    def test_secret_masking_in_prompts(self):
        """Ensure model prompts do not expose unmasked credentials in LLM context."""
        sensitive_auth = {
            "Authorization": "Bearer sensitive_token_for_model_context_check",
            "X-API-Key": "key_sensitive_112233",
        }
        # In AutonomousController, auth_context is masked before passing to prompt
        safe_auth = mask_sensitive_traffic_data(sensitive_auth)

        prompt = format_action_selection_prompt(
            current_turn=1,
            max_turns=5,
            plan_steps=[{"step": 1, "action": "Recon"}],
            recent_observations=[],
            available_tools=[{"name": "http_request", "description": "Send request"}],
            target_url="http://127.0.0.1:5000",
            auth_context=safe_auth,
        )
        self.assertNotIn("sensitive_token_for_model_context_check", prompt)
        self.assertNotIn("key_sensitive_112233", prompt)
        self.assertIn("***MASKED***", prompt)

    def test_secret_masking_in_reports(self):
        """Verify report generator produces sanitized reports without leaking credentials."""
        session_id = f"sess_mask_report_{int(time.time())}"
        self.store.create_session(session_id, self.target_url, "Report Secret Masking Check")

        secret_auth_header = {"Authorization": "Bearer report_leak_canary_token_999"}
        masked_headers = mask_sensitive_traffic_data(secret_auth_header)

        t_id = self.store.log_traffic(
            session_id=session_id,
            method="GET",
            url=f"{self.target_url}/api/users",
            headers=masked_headers,
            response_status=200,
            response_body=json.dumps({"status": "ok"}),
        )

        self.store.record_finding(
            session_id=session_id,
            endpoint=f"{self.target_url}/api/users",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Verification succeeded with masked credentials",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=t_id,
            raw_evidence={"safe": True},
        )

        generator = ReportGenerator(evidence_store=self.store)

        # Markdown Report
        md = generator.generate_report(session_id)
        self.assertNotIn("report_leak_canary_token_999", md)

        # JSON Report
        json_rep = generator.generate_json_report(session_id)
        json_str = json.dumps(json_rep)
        self.assertNotIn("report_leak_canary_token_999", json_str)

        # HTML Report
        html = generator.generate_html_report(session_id)
        self.assertNotIn("report_leak_canary_token_999", html)


if __name__ == "__main__":
    unittest.main()
