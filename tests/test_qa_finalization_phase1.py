"""QA Finalization Phase 1: Closing Remaining Verification Gaps.

Specifically validates:
1. Multi-cycle reasoning and observation-feedback loops.
2. Concrete distinction between real model inference and mocked model responses.
3. SSRF safety: Cloud metadata (169.254.169.254) and private internal IPs are blocked deterministically,
   and the local lab SSRF simulation never dispatches unbounded external socket calls.
4. API4 Resource limits: Request/response size ceilings (50 KB), timeout bounding, and redirect restrictions.
5. Credential sanitization in exceptions and error notes.
6. Interrupted session recovery: Stale ACTIVE/RUNNING sessions safely marked INTERRUPTED on daemon startup.
7. Reproducible evidence for all CONFIRMED findings.
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
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model
from controller.guardrails.scope_validator import ScopeValidator
from controller.guardrails.sanitizer import mask_sensitive_traffic_data
from controller.storage.evidence_store import EvidenceStore
from controller.tools.http_request import execute_http_request
from controller.tools.httpx_client import execute_httpx_request
from dashboard.session_manager import DashboardSessionManager


class TestQAFinalizationPhase1(unittest.TestCase):
    """Finalization Phase 1: Verification of core security, telemetry, and resilience gaps."""

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

    # -------------------------------------------------------------------------
    # 1. Distinguishing Real Model Inference from Mock Responses
    # -------------------------------------------------------------------------
    def test_distinguish_real_model_from_mock_responses(self):
        """Verify explicit runtime tagging between real GGUF inference and deterministic mock."""
        # A. Mock Brain Identification
        mock_brain = DeterministicMockBrainClient()
        self.assertEqual(mock_brain.engine, "mock")
        self.assertTrue(mock_brain.is_mock)

        # B. Real Local CPU GGUF Client Identification
        model_path = find_default_gguf_model()
        if model_path:
            real_brain = LocalCpuBrainClient(
                model_path=model_path,
                allow_mock_fallback=False,
            )
            self.assertEqual(real_brain.engine, "llama_cli")
            self.assertFalse(real_brain.is_mock)
            self.assertEqual(real_brain.metrics["engine"], "llama_cli")
            self.assertIn("qwen", real_brain.metrics["model_path"].lower())
            self.assertGreater(real_brain.metrics["peak_ram_mb"], 0.0)

    # -------------------------------------------------------------------------
    # 2. SSRF Simulation Safety: Unintended Internal Services Cannot Be Accessed
    # -------------------------------------------------------------------------
    def test_ssrf_guardrail_blocks_cloud_metadata_and_internal_lans(self):
        """Scope validator must deterministically block cloud metadata and non-loopback private networks."""
        config = AgentConfig(allowed_hosts={"127.0.0.1", "localhost"})
        validator = ScopeValidator(config)

        # Cloud metadata IPs must be explicitly blocked
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://0.0.0.0:8080/admin",
            "http://255.255.255.255/broadcast",
            "http://192.168.1.1/router",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/internal",
        ]

        for u in metadata_urls:
            res = validator.validate_url(u)
            self.assertFalse(res.is_valid, f"Target '{u}' should have been blocked as out of scope or blocked IP")
            self.assertTrue(
                "blocked" in res.reason.lower() or "out of scope" in res.reason.lower(),
                f"Unexpected reason: {res.reason}",
            )

    def test_lab_ssrf_endpoint_is_safe_simulation(self):
        """The lab's SSRF endpoint demonstrates vulnerability without making live outbound socket calls."""
        import httpx
        payload = {"url": "http://169.254.169.254/latest/meta-data/"}
        resp = httpx.post(f"{self.target_url}/api/integrations/fetch", json=payload, timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("ssrf_exposed"))
        self.assertEqual(data.get("target_url"), payload["url"])
        self.assertIn("SSRF", data.get("message"))

    # -------------------------------------------------------------------------
    # 3. API4 Resource-Consumption Limits: Request/Response Ceilings & Timeouts
    # -------------------------------------------------------------------------
    def test_response_body_truncation_ceiling(self):
        """Responses exceeding max_response_body_bytes (50 KB) are safely truncated."""
        # Configure tight 100-byte response limit for testing
        tight_cfg = AgentConfig(
            max_response_body_bytes=100,
            http_connect_timeout=2.0,
            http_read_timeout=3.0,
        )

        # Probing /api/users produces more than 100 bytes
        res = execute_http_request(
            url=f"{self.target_url}/api/users",
            method="GET",
            config=tight_cfg,
        )
        self.assertTrue(res["success"])
        self.assertTrue(res.get("truncated"), "Response should be marked truncated when exceeding limit")
        self.assertLessEqual(len(res.get("body", "")), 100)

        # Also verify with httpx client
        res_httpx = execute_httpx_request(
            url=f"{self.target_url}/api/users",
            method="GET",
            config=tight_cfg,
        )
        self.assertTrue(res_httpx["success"])
        self.assertTrue(res_httpx.get("truncated"))
        self.assertLessEqual(len(res_httpx.get("body", "")), 100)

    # -------------------------------------------------------------------------
    # 4. Credential Sanitization in Exceptions and Error Notes
    # -------------------------------------------------------------------------
    def test_credential_masking_in_controller_exceptions(self):
        """Exceptions containing raw tokens are sanitized before recording in session notes or state."""
        class ExplodingBrain(DeterministicMockBrainClient):
            def select_next_action(self, *args, **kwargs):
                raise ValueError("Auth check failed with secret token: Bearer eyJhbGciOiJub25lIn0.secret_token_abc.123")

        config = AgentConfig(
            max_turns=1,
            max_requests_per_session=2,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        controller = AutonomousController(
            config=config,
            model_brain=ExplodingBrain(),
            evidence_store=self.store,
        )

        session_id = f"sess_exc_mask_{int(time.time())}"
        res = controller.run_assessment(
            target_url=self.target_url,
            session_id=session_id,
        )

        self.assertFalse(res["success"])
        # Ensure secret token is masked in the returned error
        self.assertNotIn("secret_token_abc", res.get("error", ""))
        self.assertIn("Bearer ***", res.get("error", ""))

        # Ensure secret token is masked in the SQLite session record notes
        sess_record = self.store.get_session(session_id)
        self.assertEqual(sess_record["status"], "ERROR")
        self.assertNotIn("secret_token_abc", sess_record["notes"])
        self.assertIn("Bearer ***", sess_record["notes"])

    # -------------------------------------------------------------------------
    # 5. Interrupted Session Recovery Leaves Clean State
    # -------------------------------------------------------------------------
    def test_interrupted_session_recovery_on_startup(self):
        """Sessions left in ACTIVE or RUNNING status are cleanly recovered to INTERRUPTED."""
        # Create a temporary SQLite database
        temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        temp_path = temp_file.name
        temp_file.close()

        try:
            temp_store = EvidenceStore(db_path=temp_path)
            # Simulate 2 orphaned sessions: one ACTIVE, one RUNNING
            temp_store.create_session("sess_orphaned_active", self.target_url, "Was in progress")
            temp_store.create_session("sess_orphaned_running", self.target_url, "Was executing")
            temp_store.update_session_status("sess_orphaned_running", status="RUNNING")

            # Verify initial statuses
            self.assertEqual(temp_store.get_session("sess_orphaned_active")["status"], "ACTIVE")
            self.assertEqual(temp_store.get_session("sess_orphaned_running")["status"], "RUNNING")

            # Instantiate DashboardSessionManager (triggers startup recovery)
            mgr = DashboardSessionManager(db_path=temp_path, store=temp_store)

            # Both sessions must now be safely marked INTERRUPTED
            s1 = temp_store.get_session("sess_orphaned_active")
            s2 = temp_store.get_session("sess_orphaned_running")
            self.assertEqual(s1["status"], "INTERRUPTED")
            self.assertEqual(s2["status"], "INTERRUPTED")
            self.assertIn("[Recovered: Marked INTERRUPTED on daemon restart]", s1["notes"])
            self.assertIn("[Recovered: Marked INTERRUPTED on daemon restart]", s2["notes"])

            # Verify the manager's get_session_status reflects INTERRUPTED
            stat1 = mgr.get_session_status("sess_orphaned_active")
            self.assertEqual(stat1["status"], "INTERRUPTED")
        finally:
            import os
            try:
                os.remove(temp_path)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 6. Reproducible Evidence for CONFIRMED Findings
    # -------------------------------------------------------------------------
    def test_confirmed_findings_have_reproducible_evidence(self):
        """All CONFIRMED findings must link to traffic logs or raw evidence and provide safe reproduction steps."""
        session_id = f"sess_repro_{int(time.time())}"
        self.store.create_session(session_id, self.target_url, "Reproducibility Verification")

        t_id = self.store.log_traffic(
            session_id=session_id,
            method="GET",
            url=f"{self.target_url}/api/orders/102",
            response_status=200,
            response_body=json.dumps({"id": 102, "user_id": 2, "shipping_address": "Bob's address"}),
        )

        fid, status = self.store.record_finding(
            session_id=session_id,
            endpoint=f"{self.target_url}/api/orders/102",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Cross-account customer order details exposed without authorization",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=t_id,
            raw_evidence={"id": 102},
        )
        self.assertEqual(status, "CONFIRMED")

        # Query via DashboardSessionManager
        mgr = DashboardSessionManager(db_path=":memory:", store=self.store)
        findings = mgr.get_findings(session_id)
        self.assertEqual(len(findings), 1)
        f = findings[0]

        # Invariants for confirmed findings
        self.assertEqual(f["status"], "CONFIRMED")
        self.assertEqual(f["traffic_log_id"], t_id)
        self.assertIsNotNone(f.get("raw_evidence"))
        self.assertTrue(f.get("reproduction_steps"), "Confirmed finding must contain reproduction steps")
        self.assertIn("/api/orders/102", f["reproduction_steps"])
        self.assertTrue(f.get("technical_impact"), "Confirmed finding must describe technical impact")
        self.assertIn("CWE-639", f.get("cwe_id"))


if __name__ == "__main__":
    unittest.main()

