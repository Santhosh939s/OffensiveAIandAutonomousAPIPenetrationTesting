"""Unit and integration tests for AutonomousController and ReportGenerator."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.storage.evidence_store import EvidenceStore
from controller.reporting.report_generator import ReportGenerator


class MockApiServerHandler(BaseHTTPRequestHandler):
    """Local mock API server for integration testing."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if "/vulnerable" in self.path:
            # Simulate endpoint throwing SQL syntax error on quote probe
            if "'" in self.path:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"SQL syntax error in query SELECT * FROM items WHERE id = '")
                return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "items": [1, 2, 3]}')


class TestAutonomousController(unittest.TestCase):
    server: ClassVar[HTTPServer]
    server_thread: ClassVar[threading.Thread]
    target_url: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockApiServerHandler)
        port = cls.server.server_port
        cls.target_url = f"http://127.0.0.1:{port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.config = AgentConfig(max_turns=5, max_requests_per_session=10)
        self.store = EvidenceStore(db_path=":memory:")
        self.brain = DeterministicMockBrainClient()
        self.controller = AutonomousController(
            config=self.config,
            model_brain=self.brain,
            evidence_store=self.store,
        )

    def test_run_assessment_success(self):
        endpoints = [
            {"path": "/api/users", "method": "GET", "parameters": ["id"]},
        ]
        result = self.controller.run_assessment(
            target_url=self.target_url,
            endpoints=endpoints,
            session_notes="Integration test assessment",
        )

        self.assertTrue(result["success"])
        self.assertIsNotNone(result["session_id"])
        self.assertGreater(result["turns_taken"], 0)
        self.assertIn("# API Security Assessment Report", result["report_markdown"])

        # Verify database recorded the session, traffic, and executions
        sess_record = self.store.get_session(result["session_id"])
        self.assertIsNotNone(sess_record)
        self.assertEqual(sess_record["status"], "COMPLETED")

        traffic = self.store.get_traffic_logs(result["session_id"])
        self.assertGreater(len(traffic), 0)

        executions = self.store.get_tool_executions(result["session_id"])
        self.assertGreater(len(executions), 0)

    def test_run_assessment_out_of_scope_rejected(self):
        # Target outside localhost must be immediately rejected before starting session
        result = self.controller.run_assessment(
            target_url="http://public-target.com",
            endpoints=[{"path": "/", "method": "GET"}],
        )
        self.assertFalse(result["success"])
        self.assertIn("scope violation", result["error"].lower())

    def test_report_generator_with_session(self):
        # Run a brief assessment
        result = self.controller.run_assessment(
            target_url=self.target_url,
            endpoints=[{"path": "/api/test", "method": "GET"}],
        )
        session_id = result["session_id"]

        generator = ReportGenerator(evidence_store=self.store)
        report = generator.generate_report(session_id)

        self.assertIn("# API Security Penetration Testing Assessment Report", report)
        self.assertIn(session_id, report)
        self.assertIn("Scope and Authorization Verification", report)
        self.assertIn("Tool Activity and Execution Audit Trail", report)

    def test_controller_handles_no_action_gracefully(self):
        class ImmediateExitBrain(DeterministicMockBrainClient):
            def select_next_action(self, *args, **kwargs):
                return {
                    "action_type": "no_action",
                    "reasoning": "No actionable steps identified",
                    "error": None,
                }

        controller = AutonomousController(
            config=self.config,
            model_brain=ImmediateExitBrain(),
            evidence_store=self.store,
        )
        result = controller.run_assessment(
            target_url=self.target_url,
            endpoints=[{"path": "/api/users", "method": "GET"}],
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["turns_taken"], 0)
        self.assertIn("No actionable steps", result["termination_reason"])

    def test_controller_policy_denial_feedback_loop(self):
        class DisallowedActionBrain(DeterministicMockBrainClient):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def select_next_action(self, current_turn, max_turns, plan_steps, recent_observations, available_tools):
                self.calls += 1
                if self.calls == 1:
                    # Attempt unauthorized tool
                    return {
                        "action_type": "execute_tool",
                        "tool_name": "unauthorized_shell_tool",
                        "arguments": {"cmd": "id"},
                    }
                return {
                    "action_type": "complete",
                    "reasoning": "Finished after rejection",
                }

        controller = AutonomousController(
            config=self.config,
            model_brain=DisallowedActionBrain(),
            evidence_store=self.store,
        )
        result = controller.run_assessment(
            target_url=self.target_url,
            endpoints=[{"path": "/api/users", "method": "GET"}],
        )
        self.assertTrue(result["success"])
        executions = self.store.get_tool_executions(result["session_id"])
        self.assertEqual(len(executions), 1)
        self.assertFalse(executions[0]["approved"])
        self.assertIn("not in the authorized tool registry", executions[0]["policy_reason"])

    def test_controller_openapi_discovery_workflow(self):
        import os
        spec_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "lab", "openapi_spec.json")

        result = self.controller.run_assessment(
            target_url=self.target_url,
            spec_source=spec_path,
            session_notes="OpenAPI discovery integrated test",
        )

        self.assertTrue(result["success"])
        session_id = result["session_id"]

        # Check specification persistence
        specs = self.store.get_specifications(session_id)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]["title"], "Local Vulnerable API Laboratory")
        self.assertGreaterEqual(specs[0]["endpoints_count"], 6)


if __name__ == "__main__":
    unittest.main()

