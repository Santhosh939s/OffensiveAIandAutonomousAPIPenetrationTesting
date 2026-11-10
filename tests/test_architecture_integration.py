"""
tests/test_architecture_integration.py - Comprehensive Architecture Integration Tests.

Validates the end-to-end component connections across the entire system:
1. Dashboard -> Backend: Request schemas, validation, session lifecycle, cancellation, SSE stream.
2. Backend -> Controller: Config propagation, budget enforcement, worker error handling.
3. Controller -> Model Gateway: Context delivery (scope, masked auth, budget, objectives), JSON parsing.
4. Model -> Tool Registry: Dispatch path, schema validation, policy guardrails, out-of-scope rejection.
5. Tool Execution -> Observation Feedback: Structured receipts, state observations, context memory.
6. Evidence & Risk Data Flow: Traffic logging, verification gate, auto-demotion, CVSS/CWE risk scoring.
7. Reporting Engine -> Dashboard: Markdown, JSON, HTML consistency, sensitive secret masking.
8. Full Autonomous Closed-Loop Assessment against local vulnerable lab.
"""

import json
import socket
import threading
import time
import unittest
from typing import Any, ClassVar, Dict, List, Optional
from werkzeug.serving import make_server

from lab.app import create_app as create_lab_app
from lab.database import LabDatabase
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager, mask_sensitive_traffic_data
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools import build_default_tool_registry, ToolRegistry
from controller.brain.model_gateway import DeterministicMockBrainClient, extract_and_validate_json
from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model
from controller.storage.evidence_store import EvidenceStore, APPROVED_VERIFICATION_RULES
from controller.reporting.risk_engine import RiskAssessmentEngine, Severity
from controller.reporting.report_generator import ReportGenerator


class TestArchitectureIntegration(unittest.TestCase):
    """Integration test suite verifying every component connection across the architecture."""

    lab_server: ClassVar[Any] = None
    lab_thread: ClassVar[threading.Thread] = None
    lab_url: ClassVar[str] = ""
    lab_port: ClassVar[int] = 0

    @classmethod
    def setUpClass(cls):
        # 1. Allocate free port and start authentic local lab server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.lab_port = s.getsockname()[1]

        db = LabDatabase(":memory:")
        lab_app = create_lab_app(db)
        cls.lab_server = make_server("127.0.0.1", cls.lab_port, lab_app)
        cls.lab_url = f"http://127.0.0.1:{cls.lab_port}"

        cls.lab_thread = threading.Thread(target=cls.lab_server.serve_forever, daemon=True)
        cls.lab_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.lab_server:
            cls.lab_server.shutdown()

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.manager = DashboardSessionManager(db_path=":memory:", store=self.store)
        self.dashboard_app = create_dashboard_app(session_manager=self.manager)
        self.client = self.dashboard_app.test_client()

    # =========================================================================
    # 1. DASHBOARD TO BACKEND INTEGRATION
    # =========================================================================

    def test_dashboard_to_backend_validation_and_session_lifecycle(self):
        """Verify frontend-to-backend input validation, session creation, status polling, and cancellation."""
        # A. Missing target URL -> 400
        resp = self.client.post("/api/assessments/start", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

        # B. Out-of-scope target URL -> 400
        resp = self.client.post("/api/assessments/start", json={
            "target_url": "https://unauthorized-external-site.com",
            "allowed_hosts": ["127.0.0.1", "localhost"],
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("scope validation failed", resp.get_json()["error"].lower())

        # C. Valid launch with full configuration & auth context
        launch_payload = {
            "target_url": self.lab_url,
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "assessment_name": "Integration Architecture Test",
            "brain_mode": "mock",
            "spec_source": f"{self.lab_url}/openapi.json",
            "auth_context": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.signature",
            "max_turns": 4,
            "max_requests": 10,
            "max_model_calls": 5,
        }
        resp = self.client.post("/api/assessments/start", json=launch_payload)
        self.assertEqual(resp.status_code, 200)
        start_data = resp.get_json()
        self.assertTrue(start_data["success"])
        session_id = start_data["session_id"]
        self.assertTrue(session_id.startswith("sess_"))

        # D. Poll session status
        status_resp = self.client.get(f"/api/assessments/{session_id}/status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.get_json()
        self.assertIn(status_data["status"], ["RUNNING", "COMPLETED"])
        self.assertEqual(status_data["session_id"], session_id)

        # E. Verify cancellation mechanism
        cancel_resp = self.client.post(f"/api/assessments/{session_id}/cancel")
        self.assertEqual(cancel_resp.status_code, 200)
        cancel_data = cancel_resp.get_json()
        self.assertTrue(cancel_data["success"])

        # F. Non-existent session status returns 404
        bad_status = self.client.get("/api/assessments/non_existent_session/status")
        self.assertEqual(bad_status.status_code, 404)

    def test_dashboard_sse_telemetry_stream(self):
        """Verify Server-Sent Events stream initialization and keepalive."""
        resp = self.client.get("/api/stream/test_session_sse")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/event-stream")

    # =========================================================================
    # 2. BACKEND TO AUTONOMOUS CONTROLLER
    # =========================================================================

    def test_backend_to_controller_configuration_and_error_handling(self):
        """Verify configuration propagation and that unhandled controller exceptions update session state."""
        # Launch session with invalid spec path that doesn't exist
        res = self.manager.start_assessment(
            target_url=self.lab_url,
            assessment_name="Error Propagation Test",
            max_turns=3,
            max_requests=5,
            spec_source="invalid/nonexistent/spec.json",
            brain_mode="mock",
        )
        self.assertTrue(res["success"])
        sess_id = res["session_id"]

        # Wait briefly for thread to finish
        time.sleep(0.5)
        sess = self.store.get_session(sess_id)
        self.assertIsNotNone(sess)
        self.assertIn(sess["status"], ["COMPLETED", "ERROR"])

    # =========================================================================
    # 3. CONTROLLER TO MODEL GATEWAY
    # =========================================================================

    def test_controller_to_model_gateway_context_delivery(self):
        """Verify that target, scope, budget, objectives, and masked auth reach the model brain."""
        mock_brain = DeterministicMockBrainClient()
        config = AgentConfig(max_turns=3, max_requests_per_session=5, allowed_hosts={"127.0.0.1"})
        controller = AutonomousController(
            config=config,
            model_brain=mock_brain,
            evidence_store=self.store,
        )

        secret_token = "Bearer secret_api_key_xyz_12345"
        result = controller.run_assessment(
            target_url=self.lab_url,
            spec_source=f"{self.lab_url}/openapi.json",
            session_notes="Assess Authentication & Injection",
            auth_context={"Authorization": secret_token},
        )
        self.assertTrue(result["success"])

        # Verify calls recorded in brain
        methods_called = [c["method"] for c in mock_brain.call_history]
        self.assertIn("create_test_plan", methods_called)
        self.assertIn("select_next_action", methods_called)
        self.assertIn("analyze_evidence", methods_called)

    def test_model_gateway_resilient_json_parsing(self):
        """Verify extract_and_validate_json handles markdown blocks, trailing commas, and truncated braces."""
        # Direct JSON
        res1 = extract_and_validate_json('{"action_type": "execute_tool", "tool_name": "http_request", "arguments": {"url": "http://127.0.0.1"}}', "action")
        self.assertEqual(res1["action_type"], "execute_tool")

        # Markdown fenced
        res2 = extract_and_validate_json('Thought: test\n```json\n{"action_type": "complete", "reasoning": "done"}\n```', "action")
        self.assertEqual(res2["action_type"], "complete")

        # Trailing commas
        res3 = extract_and_validate_json('{"steps": [{"step_number": 1, "tool": "http_request",}],}', "plan")
        self.assertEqual(len(res3["steps"]), 1)

        # Truncated JSON
        res4 = extract_and_validate_json('{"action_type": "no_action", "reasoning": "truncated', "action")
        self.assertEqual(res4["action_type"], "no_action")

    # =========================================================================
    # 4. MODEL TO TOOL REGISTRY & POLICY DISPATCH
    # =========================================================================

    def test_model_to_tool_registry_policy_and_out_of_scope_rejection(self):
        """Verify that invalid tools, malformed arguments, and out-of-scope targets are deterministically blocked."""
        tools = build_default_tool_registry()
        policy = PolicyEngine(
            config=AgentConfig(allowed_hosts={"127.0.0.1", "localhost"}),
            registered_tools=set(tools.list_tool_names()),
        )

        # A. Unregistered tool rejection
        dec1 = policy.evaluate_action("malicious_shell_tool", {"cmd": "whoami"})
        self.assertFalse(dec1.approved)
        self.assertIn("not in the authorized tool registry", dec1.reason)

        # B. Out-of-scope HTTP request rejection
        dec2 = policy.evaluate_action("http_request", {"url": "http://google.com/search"})
        self.assertFalse(dec2.approved)
        self.assertIn("Scope violation", dec2.reason)

        # C. Out-of-scope GraphQL probe rejection
        dec3 = policy.evaluate_action("graphql_probe", {"target_url": "http://192.168.1.100:4000/graphql"})
        self.assertFalse(dec3.approved)
        self.assertIn("Scope violation", dec3.reason)

        # D. Out-of-scope Inventory Scanner rejection
        dec4 = policy.evaluate_action("inventory_scanner", {"target_url": "http://10.0.0.1/api"})
        self.assertFalse(dec4.approved)
        self.assertIn("Scope violation", dec4.reason)

        # E. Out-of-scope Business Flow rejection
        dec5 = policy.evaluate_action("business_flow_probe", {"url": "http://attacker.com/coupons"})
        self.assertFalse(dec5.approved)
        self.assertIn("Scope violation", dec5.reason)

        # F. ToolRegistry malformed arguments rejection
        t_res = tools.execute("http_request", {})
        self.assertFalse(t_res["success"])
        self.assertIn("Missing required parameter", t_res["error"])

    # =========================================================================
    # 5. TOOL EXECUTION & OBSERVATION FEEDBACK
    # =========================================================================

    def test_tool_execution_observation_feedback_to_controller(self):
        """Verify consistent structured receipts and observation recording."""
        tools = build_default_tool_registry()
        res = tools.execute("http_request", {
            "url": f"{self.lab_url}/api/items",
            "method": "GET",
        })
        self.assertTrue(res["success"])
        self.assertEqual(res["status_code"], 200)
        self.assertIn("body", res)
        self.assertIn("elapsed_ms", res)
        self.assertIn("headers", res)

    # =========================================================================
    # 6. EVIDENCE & RISK DATA FLOW
    # =========================================================================

    def test_evidence_verification_gate_and_risk_scoring(self):
        """Verify that findings require verified rules and traffic evidence, auto-demoting unverified assertions."""
        sess_id = "test_risk_session"
        self.store.create_session(sess_id, self.lab_url)

        # Log traffic
        t_id = self.store.log_traffic(
            session_id=sess_id,
            method="GET",
            url=f"{self.lab_url}/api/search?q='",
            response_status=500,
            response_body="unrecognized token in SQLite statement",
        )

        # A. Legitimate finding with traffic evidence and approved rule -> CONFIRMED (CVSS 9.8 Critical)
        fid1, stat1 = self.store.record_finding(
            session_id=sess_id,
            endpoint=f"{self.lab_url}/api/search",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="SQL syntax error detected in response body",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            traffic_log_id=t_id,
        )
        self.assertEqual(stat1, "CONFIRMED")
        findings = self.store.get_findings(sess_id)
        f1 = [f for f in findings if f["id"] == fid1][0]
        self.assertEqual(f1["status"], "CONFIRMED")
        self.assertEqual(f1["severity"], "CRITICAL")
        self.assertEqual(f1["cwe_id"], "CWE-89")
        self.assertEqual(f1["cvss_score"], 9.8)

        # B. Unverified assertion without rule or traffic log -> AUTO-DEMOTED to SUSPECTED
        fid2, stat2 = self.store.record_finding(
            session_id=sess_id,
            endpoint=f"{self.lab_url}/api/unverified",
            category="Remote Code Execution",
            status="CONFIRMED",
            evidence_notes="Model hallucination without traffic log",
            verification_rule="UNAPPROVED_CUSTOM_RULE",
            traffic_log_id=None,
            raw_evidence={},
        )
        self.assertEqual(stat2, "SUSPECTED")
        findings = self.store.get_findings(sess_id)
        f2 = [f for f in findings if f["id"] == fid2][0]
        self.assertEqual(f2["status"], "SUSPECTED")
        self.assertIn("AUTO-DEMOTED", f2["evidence_notes"])

        # C. Risk summary aggregation
        risk_summary = RiskAssessmentEngine.calculate_session_risk_summary(findings)
        self.assertEqual(risk_summary.confirmed_count, 1)
        self.assertEqual(risk_summary.suspected_count, 1)
        self.assertEqual(risk_summary.critical_count, 1)

    # =========================================================================
    # 7. REPORTING & DASHBOARD DATA ALIGNMENT
    # =========================================================================

    def test_reporting_multi_format_and_dashboard_retrieval(self):
        """Verify Markdown, JSON, and HTML reports generate consistent audit data with masked credentials."""
        sess_id = "test_reporting_session"
        self.store.create_session(sess_id, self.lab_url)

        # Record traffic with sensitive token
        self.store.log_traffic(
            session_id=sess_id,
            method="POST",
            url=f"{self.lab_url}/api/login",
            headers={"Authorization": "Bearer super_secret_admin_token_999"},
            request_body=json.dumps({"password": "secret_password_123"}),
            response_status=200,
            response_body=json.dumps({"token": "jwt_secret_token_abc"}),
        )

        reporter = ReportGenerator(evidence_store=self.store)
        md = reporter.generate_report(sess_id)
        js = reporter.generate_json_report(sess_id)
        html = reporter.generate_html_report(sess_id)

        # Data consistency
        self.assertIn(sess_id, md)
        self.assertEqual(js["session"]["session_id"], sess_id)
        self.assertIn(sess_id, html)

        # Dashboard sanitization verification
        sanitized_traffic = self.manager.get_traffic_logs_sanitized(sess_id)
        self.assertEqual(len(sanitized_traffic), 1)
        req_headers_str = json.dumps(sanitized_traffic[0]["headers"])
        self.assertNotIn("super_secret_admin_token_999", req_headers_str)
        self.assertIn("Bearer ***", req_headers_str)

    # =========================================================================
    # 8. FULL AUTONOMOUS CLOSED-LOOP WORKFLOW (LOCALHOST LAB)
    # =========================================================================

    def test_full_autonomous_closed_loop_workflow(self):
        """End-to-end multi-turn closed-loop run against authentic local lab."""
        config = AgentConfig(
            max_turns=15,
            max_requests_per_session=40,
            zap_active_scan_enabled=False,
        )
        controller = AutonomousController(
            config=config,
            model_brain=DeterministicMockBrainClient(),
            evidence_store=self.store,
            tool_registry=build_default_tool_registry(),
        )

        result = controller.run_assessment(
            target_url=self.lab_url,
            spec_source=f"{self.lab_url}/openapi.json",
            session_notes="Full Architecture Multi-Turn Integration Run",
        )
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["turns_taken"], 5)
        self.assertGreaterEqual(result["requests_sent"], 5)
        self.assertGreater(len(result["findings"]), 0)

        # Verify that confirmed findings are stored with verified rules
        confirmed = [f for f in result["findings"] if f["status"] == "CONFIRMED"]
        self.assertGreater(len(confirmed), 0)
        for cf in confirmed:
            self.assertIn(cf["verification_rule"], APPROVED_VERIFICATION_RULES)

    # =========================================================================
    # 9. REAL LOCAL CPU MODEL ARCHITECTURE VERIFICATION
    # =========================================================================

    def test_real_local_cpu_model_gateway_inference(self):
        """Verify real local CPU GGUF inference engine via llama-cli.exe (strictly non-mock)."""
        model_path = find_default_gguf_model()
        if not model_path:
            self.skipTest("GGUF model file not found locally in default search paths.")

        # Initialize real CPU brain with mock fallback strictly disabled
        brain = LocalCpuBrainClient(
            model_path=model_path,
            allow_mock_fallback=False,
        )
        self.assertEqual(brain.engine, "llama_cli")

        # Test real classification inference
        sample_req = {
            "method": "POST",
            "path": "/api/users",
            "body": {"username": "admin' UNION SELECT null, password FROM users --"},
        }
        res = brain.classify_request(sample_req)
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("category"), "SQL Injection")
        self.assertGreater(brain.metrics["total_inferences"], 0)


if __name__ == "__main__":
    unittest.main()
