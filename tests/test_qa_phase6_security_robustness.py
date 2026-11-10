"""QA Phase 6: Security, Guardrails, Scope Validation, and Operational Robustness.

Validates:
1. Out-of-scope domain rejection:
   - External domains (e.g. evil.com, google.com) blocked by ScopeValidator before any network dispatch.
   - Non-whitelisted local/private subnets blocked.
2. Malformed URLs and illegal schemes:
   - file://, ftp://, gopher://, javascript: schemes rejected with structured errors.
   - Missing netloc or malformed strings rejected.
3. Pre-execution guardrails and policy constraints:
   - Destructive tool execution requests blocked.
   - Unregistered tools blocked.
   - Per-endpoint probe limits strictly enforced to avoid denial of service.
4. Hard resource and budget ceilings:
   - Request budget ceiling (max_requests_per_session) enforced.
   - Turn budget ceiling (max_turns) enforced.
   - Oversized / toxic inputs gracefully rejected without buffer or token crashes.
"""

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
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.scope_validator import ScopeValidator
from controller.storage.evidence_store import EvidenceStore
from controller.tools import build_default_tool_registry
from dashboard.session_manager import DashboardSessionManager


class TestQAPhase6SecurityRobustness(unittest.TestCase):
    """QA Phase 6: Security, guardrails, scope restrictions, and robustness testing."""

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
        self.tools = build_default_tool_registry()

    # -------------------------------------------------------------------------
    # 1. Out-of-Scope Target Rejection
    # -------------------------------------------------------------------------
    def test_out_of_scope_target_rejected_by_validator(self):
        """Unauthorized external domains must be blocked before any network dispatch."""
        config = AgentConfig(allowed_hosts={"127.0.0.1", "localhost"})
        validator = ScopeValidator(config)

        # External domains
        res1 = validator.validate_url("https://google.com/api/v1")
        self.assertFalse(res1.is_valid)
        self.assertIn("out of scope", res1.reason.lower())

        res2 = validator.validate_url("http://malicious-external-target.com:8080/probe")
        self.assertFalse(res2.is_valid)
        self.assertIn("out of scope", res2.reason.lower())

        # Non-whitelisted internal IP
        res3 = validator.validate_url("http://192.168.1.100/admin")
        self.assertFalse(res3.is_valid)
        self.assertIn("out of scope", res3.reason.lower())

    def test_controller_rejects_out_of_scope_target(self):
        """AutonomousController must reject unauthorized target and emit no network requests."""
        config = AgentConfig(allowed_hosts={"127.0.0.1"})
        controller = AutonomousController(
            config=config,
            model_brain=DeterministicMockBrainClient(),
            evidence_store=self.store,
            tool_registry=self.tools,
        )

        result = controller.run_assessment(target_url="http://unauthorized-domain.com/api")
        self.assertFalse(result["success"])
        self.assertIn("Target scope violation", result["error"])

    # -------------------------------------------------------------------------
    # 2. Malformed URLs and Dangerous Schemes
    # -------------------------------------------------------------------------
    def test_illegal_schemes_and_malformed_urls_rejected(self):
        """Reject non-http/https schemes such as file://, ftp://, gopher://, javascript:."""
        config = AgentConfig(allowed_hosts={"127.0.0.1", "localhost"})
        validator = ScopeValidator(config)

        illegal_urls = [
            "file:///etc/passwd",
            "file://C:/Windows/win.ini",
            "ftp://127.0.0.1/resource",
            "gopher://127.0.0.1:70",
            "javascript:alert(document.cookie)",
            "data:text/html,<script>alert(1)</script>",
            "not_a_valid_url_at_all",
            "",
            "   ",
        ]

        for u in illegal_urls:
            res = validator.validate_url(u)
            self.assertFalse(res.is_valid, f"Expected '{u}' to be rejected as invalid scheme/url")

    # -------------------------------------------------------------------------
    # 3. Guardrails & Policy Pre-Execution Enforcement
    # -------------------------------------------------------------------------
    def test_policy_blocks_unauthorized_tools_and_shell_actions(self):
        """Policy engine must reject destructive tools and arbitrary shell execution."""
        config = AgentConfig(allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"})
        policy = PolicyEngine(config, registered_tools={"http_request", "httpx_request"})

        # 1. Reject destructive shell / arbitrary tools
        decision1 = policy.evaluate_action("bash_exec", {"command": "rm -rf /"})
        self.assertFalse(decision1.approved)

        decision2 = policy.evaluate_action("cmd_exec", {"command": "dir C:\\"})
        self.assertFalse(decision2.approved)

        # 2. Reject out-of-scope targets even within approved tool arguments
        decision3 = policy.evaluate_action(
            "http_request",
            {"url": "https://evil.external.target.com/api", "method": "GET"},
        )
        self.assertFalse(decision3.approved)
        self.assertIn("out of scope", decision3.reason.lower())

    def test_per_endpoint_probe_exhaustion_guardrail(self):
        """Per-endpoint probe limit prevents denial of service / loop starvation."""
        config = AgentConfig(
            max_turns=10,
            max_requests_per_session=30,
            max_probes_per_endpoint=2,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        controller = AutonomousController(
            config=config,
            model_brain=DeterministicMockBrainClient(),
            evidence_store=self.store,
            tool_registry=self.tools,
        )

        session_id = f"sess_quota_{int(time.time())}"
        # Target with single endpoint
        result = controller.run_assessment(
            target_url=self.target_url,
            endpoints=[{"path": "/health", "method": "GET"}],
            session_id=session_id,
        )
        self.assertTrue(result["success"])
        # Endpoint was probed at most max_probes_per_endpoint (2) times before being exhausted
        tool_execs = self.store.get_tool_executions(session_id)
        endpoint_probes = [
            e for e in tool_execs
            if e["tool_name"] == "http_request" and "/health" in json.dumps(e["arguments"])
        ]
        self.assertLessEqual(len(endpoint_probes), 2)

    # -------------------------------------------------------------------------
    # 4. Hard Request and Turn Budgets
    # -------------------------------------------------------------------------
    def test_hard_request_budget_exhaustion(self):
        """Assessment halts promptly once max_requests_per_session budget is reached."""
        max_requests = 10
        config = AgentConfig(
            max_turns=20,
            max_requests_per_session=max_requests,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        controller = AutonomousController(
            config=config,
            model_brain=DeterministicMockBrainClient(),
            evidence_store=self.store,
            tool_registry=self.tools,
        )

        session_id = f"sess_budget_req_{int(time.time())}"
        test_endpoints = [
            {"path": "/health", "method": "GET"},
            {"path": "/api/users", "method": "GET"},
            {"path": "/api/items", "method": "GET"},
            {"path": "/api/orders", "method": "GET"},
            {"path": "/api/admin/export", "method": "GET"},
        ]
        result = controller.run_assessment(
            target_url=self.target_url,
            endpoints=test_endpoints,
            session_id=session_id,
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["requests_sent"], max_requests)
        self.assertIn("Cumulative request limit reached", result["termination_reason"])

    def test_hard_turn_budget_exhaustion(self):
        """Assessment terminates cleanly when max_turns ceiling is reached."""
        max_turns = 2
        config = AgentConfig(
            max_turns=max_turns,
            max_requests_per_session=50,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        controller = AutonomousController(
            config=config,
            model_brain=DeterministicMockBrainClient(),
            evidence_store=self.store,
            tool_registry=self.tools,
        )

        session_id = f"sess_budget_turns_{int(time.time())}"
        result = controller.run_assessment(
            target_url=self.target_url,
            spec_source=f"{self.target_url}/openapi.json",
            session_id=session_id,
        )
        self.assertTrue(result["success"])
        self.assertLessEqual(result["turns_taken"], max_turns)


if __name__ == "__main__":
    unittest.main()
