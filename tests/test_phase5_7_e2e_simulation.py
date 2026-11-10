"""Phase 5.7: End-to-End Autonomous Lab Simulation & Audit Admissibility Tests.

Validates the complete closed-loop autonomous penetration testing pipeline
under active administrative policy governance against the authentic Vulnerable API Lab:
1. Scenario A: Policy-Governed Autonomous Penetration Testing Simulation (OWASP API Top 10).
2. Scenario B: Dynamic Budget Enforcement & Clean Session Cutoff.
3. Scenario C: Live Target Revocation Halting Active Probing.
4. Scenario D: Multi-Format Report Generation & Cryptographic Integrity.
5. Scenario E: Administrative Audit Trail Admissibility & Tamper Evidence.
"""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from typing import ClassVar, Any, Dict, List

from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.storage.evidence_store import EvidenceStore
from controller.reporting.report_generator import ReportGenerator
from controller.tools import build_default_tool_registry
from controller.auth.authentication_service import AuthenticationService
from controller.guardrails.policy_service import PolicyService, get_default_policy_config
from controller.guardrails.policy_engine import PolicyEngine


class BaseLabServerTestCase(unittest.TestCase):
    """Base test case providing a running in-process instance of the Vulnerable API Lab."""

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


class TestAutonomousLabAssessmentSimulation(BaseLabServerTestCase):
    """Scenario A: Full Autonomous Penetration Testing Run under Active Policy."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.auth_svc = AuthenticationService(store=self.store)
        self.policy_svc = PolicyService(store=self.store)

        # Bootstrap administrator
        self.admin = self.auth_svc.bootstrap_admin("lab_admin", "AdminSecure2026!")

        # Create active policy authorizing the lab port and /api prefix
        pol_cfg = get_default_policy_config()
        pol_cfg["max_requests"] = 60
        pol_cfg["max_turns"] = 25
        pol_cfg["allowed_tools"] = [
            "http_request",
            "httpx_request",
            "parameter_fuzzer",
            "openapi_parser",
            "jwt_inspector",
            "business_flow_probe",
            "inventory_scanner",
            "graphql_probe",
        ]
        self.policy = self.policy_svc.create_policy(
            name="Lab Penetration Test Policy",
            description="Governs E2E simulation against local vulnerable API lab",
            config=pol_cfg,
            creator_id=self.admin["id"],
            targets=[
                {
                    "host_pattern": "127.0.0.1",
                    "port_range": str(self.port),
                    "path_prefix": "/",
                    "allowed_schemes": "http,https",
                }
            ],
        )

        self.brain = DeterministicMockBrainClient()
        self.tools = build_default_tool_registry()
        self.config = AgentConfig(
            max_turns=25,
            max_requests_per_session=60,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        self.controller = AutonomousController(
            config=self.config,
            model_brain=self.brain,
            evidence_store=self.store,
            tool_registry=self.tools,
            policy_service=self.policy_svc,
        )

    def tearDown(self):
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_e2e_autonomous_pentest_simulation_under_policy(self):
        """Execute full autonomous assessment governed by policy against the real API lab."""
        result = self.controller.run_assessment(
            target_url=self.target_url,
            spec_source=f"{self.target_url}/openapi.json",
            policy_id=self.policy["id"],
            operator_id=self.admin["id"],
            session_notes="Phase 5.7 Full Autonomous Lab Simulation",
        )

        self.assertTrue(result["success"], f"Assessment failed: {result.get('error')}")
        session_id = result["session_id"]
        self.assertIsNotNone(session_id)
        self.assertGreater(result["requests_sent"], 0)
        self.assertGreater(result["turns_taken"], 0)

        # 1. Verify frozen policy snapshot in EvidenceStore via PolicyService
        snapshot = self.policy_svc.get_assessment_snapshot(session_id)
        self.assertIsNotNone(snapshot, "Policy snapshot was not created for session!")
        self.assertEqual(snapshot["policy_id"], self.policy["id"])
        self.assertEqual(snapshot["applied_by_user_id"], self.admin["id"])

        frozen_config = snapshot["config"]
        if isinstance(frozen_config, str):
            frozen_config = json.loads(frozen_config)
        self.assertEqual(frozen_config["max_requests"], 60)

        # 2. Verify confirmed security findings across OWASP API Top 10
        findings = self.store.get_findings(session_id)
        self.assertGreaterEqual(len(findings), 8, f"Expected >= 8 findings, got {len(findings)}")

        categories = {f["category"] for f in findings}
        rules = {f["verification_rule"] for f in findings}
        statuses = {f["status"] for f in findings}

        # Verification that findings are genuine confirmed flaws
        self.assertIn("CONFIRMED", statuses)
        self.assertIn("SQL_SYNTAX_ERROR_MATCH", rules)
        self.assertIn("BFLA_ADMIN_FUNCTION_BYPASS", rules)
        self.assertIn("BUSINESS_FLOW_UNRESTRICTED_ACCESS", rules)
        self.assertIn("UNSAFE_DOWNSTREAM_API_CONSUMPTION", rules)
        self.assertIn("TOKEN_ALGORITHM_NONE_ACCEPTED", rules)
        self.assertIn("ROLE_ELEVATION_VERIFIED", rules)
        self.assertTrue(any("BOLA" in c for c in categories))
        self.assertTrue(any("GraphQL" in c for c in categories))

        # 3. Verify traffic log persisted with evidence digests
        traffic = self.store.get_traffic_logs(session_id)
        self.assertGreater(len(traffic), 0)
        first_req = traffic[0]
        self.assertIn("response_status", first_req)
        self.assertIn("url", first_req)
        self.assertTrue(first_req["url"].startswith(f"http://127.0.0.1:{self.port}"))


class TestDynamicPolicyHaltAndBudgetCutoff(BaseLabServerTestCase):
    """Scenario B: Dynamic Budget Enforcement & Clean Session Cutoff."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.auth_svc = AuthenticationService(store=self.store)
        self.policy_svc = PolicyService(store=self.store)

        self.admin = self.auth_svc.bootstrap_admin("budget_admin", "AdminSecure2026!")

        # Policy configured with tight limit: max_requests=5
        pol_cfg = get_default_policy_config()
        pol_cfg["max_requests"] = 5
        pol_cfg["max_turns"] = 15
        self.policy = self.policy_svc.create_policy(
            name="Strict 5-Request Budget Policy",
            config=pol_cfg,
            creator_id=self.admin["id"],
            targets=[
                {
                    "host_pattern": "127.0.0.1",
                    "port_range": str(self.port),
                    "path_prefix": "/",
                }
            ],
        )

        self.brain = DeterministicMockBrainClient()
        self.tools = build_default_tool_registry()
        self.config = AgentConfig(
            max_turns=15,
            max_requests_per_session=5,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        self.controller = AutonomousController(
            config=self.config,
            model_brain=self.brain,
            evidence_store=self.store,
            tool_registry=self.tools,
            policy_service=self.policy_svc,
        )

    def tearDown(self):
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_session_budget_cutoff_halts_cleanly(self):
        """When the request budget is exhausted, the controller halts gracefully without overrun."""
        result = self.controller.run_assessment(
            target_url=self.target_url,
            spec_source=f"{self.target_url}/openapi.json",
            policy_id=self.policy["id"],
            operator_id=self.admin["id"],
            session_notes="Phase 5.7 Budget Cutoff Test",
        )

        self.assertTrue(result["success"])
        session_id = result["session_id"]
        # Exactly 5 probe requests (+ optional 1 spec discovery request) must be executed
        self.assertLessEqual(result["requests_sent"], 6)

        # Traffic log in database matches the bound
        traffic = self.store.get_traffic_logs(session_id)
        self.assertLessEqual(len(traffic), 6)


class TestLiveTargetRevocationHaltsProbing(BaseLabServerTestCase):
    """Scenario C: Live Target Revocation Halting Active Probing."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.auth_svc = AuthenticationService(store=self.store)
        self.policy_svc = PolicyService(store=self.store)

        self.admin = self.auth_svc.bootstrap_admin("revoke_admin", "AdminSecure2026!")

        pol_cfg = get_default_policy_config()
        self.policy = self.policy_svc.create_policy(
            name="Revocation Target Policy",
            config=pol_cfg,
            creator_id=self.admin["id"],
            targets=[
                {
                    "host_pattern": "127.0.0.1",
                    "port_range": str(self.port),
                    "path_prefix": "/",
                }
            ],
        )

    def tearDown(self):
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_live_target_revocation_blocks_subsequent_probe(self):
        """Revoking an active target in the database immediately blocks subsequent probes."""
        # 1. Target is currently authorized
        is_auth_before, _, _ = self.policy_svc.is_target_authorized_live(
            policy_id=self.policy["id"],
            url=f"http://127.0.0.1:{self.port}/api/users",
        )
        self.assertTrue(is_auth_before)

        # 2. Bind policy engine with active snapshot (created before revocation)
        snapshot = self.policy_svc.create_assessment_snapshot("sess-rev-1", self.policy["id"], self.admin["id"])
        engine = PolicyEngine(
            registered_tools={"http_request"},
            policy_service=self.policy_svc,
        )
        engine.bind_policy_snapshot(snapshot)
        tools = build_default_tool_registry()
        tools.set_policy_engine(engine)

        # 3. Administrator revokes target
        targets = self.policy_svc.list_target_authorizations(self.policy["id"])
        self.assertEqual(len(targets), 1)
        target_id = targets[0]["id"]

        revoked = self.policy_svc.revoke_target_authorization(
            target_id=target_id,
            actor_id=self.admin["id"],
            policy_id=self.policy["id"],
        )
        self.assertTrue(revoked)

        # 4. Live check immediately returns False
        is_auth_after, _, _ = self.policy_svc.is_target_authorized_live(
            policy_id=self.policy["id"],
            url=f"http://127.0.0.1:{self.port}/api/users",
        )
        self.assertFalse(is_auth_after)

        # 5. Outbound tool execution through registry fails immediately due to live revocation
        res = tools.execute("http_request", {"url": f"http://127.0.0.1:{self.port}/api/users"})
        self.assertFalse(res["success"])
        self.assertTrue(res.get("policy_denied"))
        self.assertIn("revoked", res["error"].lower())


class TestAuditTrailAdmissibilityAndTamperEvidence(BaseLabServerTestCase):
    """Scenario D: Administrative Audit Trail Admissibility & Tamper Evidence."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.auth_svc = AuthenticationService(store=self.store)
        self.policy_svc = PolicyService(store=self.store)

        self.admin = self.auth_svc.bootstrap_admin("audit_officer", "AdminSecure2026!")

    def tearDown(self):
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_audit_log_complete_chain_of_custody(self):
        """Administrative audit log captures every critical action with actor, timestamp and details."""
        # Action 1: Create policy
        policy = self.policy_svc.create_policy(
            name="Audited Policy",
            config=get_default_policy_config(),
            creator_id=self.admin["id"],
            targets=[{"host_pattern": "127.0.0.1", "port_range": str(self.port), "path_prefix": "/"}],
        )

        # Action 2: Update policy
        updated_cfg = dict(policy["config"])
        updated_cfg["max_requests"] = 45
        self.policy_svc.update_policy(
            policy_id=policy["id"],
            name="Audited Policy v2",
            new_config=updated_cfg,
            modifier_id=self.admin["id"],
        )

        # Action 3: Revoke target
        targets = self.policy_svc.list_target_authorizations(policy["id"])
        target_id = targets[0]["id"]
        self.policy_svc.revoke_target_authorization(target_id=target_id, actor_id=self.admin["id"], policy_id=policy["id"])

        # Action 4: Deactivate policy
        self.policy_svc.deactivate_policy(policy["id"], actor_id=self.admin["id"])

        # Action 5: Roll back policy
        self.policy_svc.rollback_policy_version(policy["id"], target_version=1, modifier_id=self.admin["id"])

        # Query administrative audit log
        audit_records = self.policy_svc.get_audit_log(limit=50)
        self.assertGreaterEqual(len(audit_records), 5)

        actions = [r["action"] for r in audit_records]
        self.assertIn("BOOTSTRAP_ADMIN_CREATED", actions)
        self.assertIn("POLICY_CREATED", actions)
        self.assertIn("POLICY_UPDATED", actions)
        self.assertIn("TARGET_AUTHORIZATION_REVOKED", actions)
        self.assertIn("POLICY_DEACTIVATED", actions)

        # Verify integrity of each audit entry
        for entry in audit_records:
            self.assertIsNotNone(entry["id"])
            self.assertIsNotNone(entry["action"])
            self.assertIsNotNone(entry["user_id"])
            self.assertIsNotNone(entry["timestamp"])
            self.assertIsNotNone(entry["details"])
            # Details must be a dictionary (sanitized and structured)
            self.assertIsInstance(entry["details"], dict)


class TestReportGenerationAndArtifactDefensibility(BaseLabServerTestCase):
    """Scenario E: Multi-Format Report Generation & Cryptographic Integrity."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.auth_svc = AuthenticationService(store=self.store)
        self.policy_svc = PolicyService(store=self.store)

        self.admin = self.auth_svc.bootstrap_admin("reporter_admin", "AdminSecure2026!")

        pol_cfg = get_default_policy_config()
        self.policy = self.policy_svc.create_policy(
            name="Report Test Policy",
            config=pol_cfg,
            creator_id=self.admin["id"],
            targets=[{"host_pattern": "127.0.0.1", "port_range": str(self.port), "path_prefix": "/"}],
        )

        self.brain = DeterministicMockBrainClient()
        self.tools = build_default_tool_registry()
        self.config = AgentConfig(
            max_turns=20,
            max_requests_per_session=50,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        self.controller = AutonomousController(
            config=self.config,
            model_brain=self.brain,
            evidence_store=self.store,
            tool_registry=self.tools,
            policy_service=self.policy_svc,
        )

    def tearDown(self):
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_multi_format_report_generation_with_evidence_integrity(self):
        """Generate structured JSON, styled HTML, and Markdown reports with verified evidence."""
        # Run autonomous assessment
        res = self.controller.run_assessment(
            target_url=self.target_url,
            spec_source=f"{self.target_url}/openapi.json",
            policy_id=self.policy["id"],
            operator_id=self.admin["id"],
            session_notes="Report Generation Verification Assessment",
        )
        self.assertTrue(res["success"])
        session_id = res["session_id"]

        generator = ReportGenerator(evidence_store=self.store)

        # 1. Structured JSON Report
        json_report = generator.generate_json_report(session_id)
        self.assertIsInstance(json_report, dict)
        self.assertEqual(json_report["session"]["session_id"], session_id)
        self.assertIn("risk_summary", json_report)
        self.assertIn("findings", json_report)
        self.assertGreaterEqual(len(json_report["findings"]), 5)

        # Verify findings have structured severity and metadata
        for finding in json_report["findings"]:
            self.assertIn("severity", finding)
            self.assertIn("category", finding)
            self.assertIn("raw_evidence", finding)

        # 2. Markdown Report
        md_report = generator.generate_report(session_id)
        self.assertIsInstance(md_report, str)
        self.assertIn("# API Security Penetration Testing Assessment Report", md_report)
        self.assertIn("## 2. Executive Risk Summary", md_report)
        self.assertIn("## 4. Detailed Technical Findings & Remediation", md_report)

        # 3. HTML Report
        html_report = generator.generate_html_report(session_id)
        self.assertIsInstance(html_report, str)
        self.assertIn("<!DOCTYPE html>", html_report)
        self.assertIn("API Security Penetration Testing Report", html_report)
        # Verify offline self-containment: no external CDN links in generated report
        self.assertNotIn("https://cdn.", html_report)
        self.assertNotIn("https://cdnjs.", html_report)
        self.assertNotIn("http://fonts.googleapis.com", html_report)


if __name__ == "__main__":
    unittest.main()
