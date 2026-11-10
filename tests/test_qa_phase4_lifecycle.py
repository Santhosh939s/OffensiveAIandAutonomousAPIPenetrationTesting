"""QA Phase 4: Assessment Lifecycle, Concurrency, Cancellation, Error Recovery, and Diffing.

Validates:
1. Multi-session concurrency: concurrent assessment execution without database contention.
2. Active cooperative cancellation: immediate status transition to CANCELLED and clean worker termination.
3. Model failure and timeout recovery: handling model exceptions gracefully without database corruption.
4. Historical run restoration: loading past runs from SQLite with full integrity of findings and traffic.
5. Cross-session regression diffing: identifying new, resolved, and persistent vulnerabilities across sessions.
"""

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
from controller.tools import build_default_tool_registry
from dashboard.session_manager import DashboardSessionManager


class FaultyMockBrain(DeterministicMockBrainClient):
    """Mock brain that deliberately injects runtime exceptions for resilience testing."""

    def __init__(self, fail_on_action: bool = False, fail_on_evidence: bool = False):
        super().__init__()
        self.fail_on_action = fail_on_action
        self.fail_on_evidence = fail_on_evidence

    def select_next_action(self, *args, **kwargs) -> Dict[str, Any]:
        if self.fail_on_action:
            raise RuntimeError("Simulated unhandled model crash during action selection")
        return super().select_next_action(*args, **kwargs)

    def analyze_evidence(self, *args, **kwargs) -> Dict[str, Any]:
        if self.fail_on_evidence:
            raise RuntimeError("Simulated model timeout/failure during evidence analysis")
        return super().analyze_evidence(*args, **kwargs)


class TestQAPhase4Lifecycle(unittest.TestCase):
    """QA Phase 4: Lifecycle management, concurrency, cancellation, fault tolerance, and diffing."""

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
        # Use an isolated SQLite file on disk so multiple connections & restarts can be tested
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        self.store = EvidenceStore(db_path=self.temp_db_path)
        self.session_mgr = DashboardSessionManager(db_path=self.temp_db_path, store=self.store)

    def tearDown(self):
        import os
        try:
            os.remove(self.temp_db_path)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 1. Multi-Session Concurrency
    # -------------------------------------------------------------------------
    def test_multi_session_concurrency_execution(self):
        """Execute 3 concurrent sessions simultaneously without database lock collisions."""
        session_ids = []
        for i in range(3):
            sess = self.session_mgr.start_assessment(
                target_url=self.target_url,
                assessment_name=f"Concurrent Test #{i+1}",
                max_turns=2,
                max_requests=5,
                brain_mode="mock",
            )
            self.assertTrue(sess.get("success"), sess.get("error"))
            session_ids.append(sess["session_id"])

        # Wait for all background threads to complete
        timeout = 10.0
        start = time.time()
        while time.time() - start < timeout:
            all_done = True
            for s_id in session_ids:
                status = self.session_mgr.get_session_status(s_id)
                if status.get("status") not in ("COMPLETED", "TIMEOUT", "ERROR"):
                    all_done = False
                    break
            if all_done:
                break
            time.sleep(0.3)

        for s_id in session_ids:
            final_status = self.session_mgr.get_session_status(s_id)
            self.assertIn(final_status.get("status"), ("COMPLETED", "TIMEOUT"))
            traffic = self.store.get_traffic_logs(s_id)
            self.assertGreater(len(traffic), 0)

    # -------------------------------------------------------------------------
    # 2. Cooperative Cancellation
    # -------------------------------------------------------------------------
    def test_cooperative_cancellation_lifecycle(self):
        """Request cancellation of a running assessment and verify graceful halt."""
        sess = self.session_mgr.start_assessment(
            target_url=self.target_url,
            assessment_name="Cancellation Test",
            max_turns=25,
            max_requests=50,
            brain_mode="mock",
        )
        self.assertTrue(sess.get("success"))
        session_id = sess["session_id"]

        # Small yield to let session start
        time.sleep(0.05)

        # Trigger cancellation
        cancel_res = self.session_mgr.cancel_assessment(session_id)
        self.assertTrue(cancel_res.get("success"))
        self.assertEqual(cancel_res.get("status"), "CANCELLED")

        # Allow thread to handle cancellation
        time.sleep(0.6)

        status = self.session_mgr.get_session_status(session_id)
        self.assertEqual(status.get("status"), "CANCELLED")

    # -------------------------------------------------------------------------
    # 3. Model Failure and Error Recovery
    # -------------------------------------------------------------------------
    def test_model_exception_recovery_does_not_corrupt_database(self):
        """Verify that an unexpected crash in the model client is handled gracefully."""
        faulty_brain = FaultyMockBrain(fail_on_action=True)
        config = AgentConfig(
            max_turns=3,
            max_requests_per_session=10,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        controller = AutonomousController(
            config=config,
            model_brain=faulty_brain,
            evidence_store=self.store,
            tool_registry=build_default_tool_registry(),
        )

        session_id = f"sess_fault_test_{int(time.time())}"
        result = controller.run_assessment(
            target_url=self.target_url,
            session_id=session_id,
        )

        # Controller caught exception and returned structured failure
        self.assertFalse(result.get("success"))
        self.assertIn("error", result)
        self.assertIn("Simulated unhandled model crash", result["error"])

        # Database session was marked ERROR rather than remaining orphaned ACTIVE
        sess_record = self.store.get_session(session_id)
        self.assertEqual(sess_record["status"], "ERROR")
        self.assertIn("Simulated unhandled model crash", sess_record["notes"])

    # -------------------------------------------------------------------------
    # 4. Historical Run Re-opening & Persistence
    # -------------------------------------------------------------------------
    def test_historical_session_reopening(self):
        """Verify that historical sessions persist and can be reopened across manager instances."""
        hist_id = f"sess_hist_{int(time.time())}"
        self.store.create_session(hist_id, self.target_url, "Archived Test Run")
        self.store.log_traffic(hist_id, "GET", f"{self.target_url}/health", response_status=200)
        self.store.record_finding(
            session_id=hist_id,
            endpoint=f"{self.target_url}/api/users/2",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Historical finding",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=1,
            raw_evidence={"user": "bob"},
        )
        self.store.update_session_status(hist_id, "COMPLETED", turns_taken=3, requests_sent=6)

        # Simulate complete application restart with a fresh DashboardSessionManager instance
        new_mgr = DashboardSessionManager(db_path=self.temp_db_path)
        all_sessions = new_mgr.list_sessions()
        matched = [s for s in all_sessions if s["session_id"] == hist_id]
        self.assertEqual(len(matched), 1)

        hist_status = new_mgr.get_session_status(hist_id)
        self.assertEqual(hist_status["session_id"], hist_id)
        self.assertEqual(hist_status["status"], "COMPLETED")
        self.assertEqual(hist_status["findings_count"], 1)

        findings = new_mgr.get_findings(hist_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "BOLA / IDOR")

    # -------------------------------------------------------------------------
    # 5. Cross-Session Diffing & Regression Tracking
    # -------------------------------------------------------------------------
    def test_cross_session_diffing_regression_analysis(self):
        """Verify regression diff calculation: new, resolved, and persistent findings."""
        sess_base = f"sess_diff_base_{int(time.time())}"
        sess_next = f"sess_diff_next_{int(time.time())}"

        self.store.create_session(sess_base, self.target_url, "Baseline Scan")
        self.store.create_session(sess_next, self.target_url, "Regression Scan")

        # Session Base: Findings A & B
        self.store.record_finding(
            session_id=sess_base,
            endpoint=f"{self.target_url}/api/users/2",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Vulnerability A",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=1,
            raw_evidence={"dummy": 1},
        )
        self.store.record_finding(
            session_id=sess_base,
            endpoint=f"{self.target_url}/api/search",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="Vulnerability B",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            traffic_log_id=2,
            raw_evidence={"dummy": 2},
        )

        # Session Next: Vulnerability A persists, Vulnerability B is resolved, Vulnerability C is new
        self.store.record_finding(
            session_id=sess_next,
            endpoint=f"{self.target_url}/api/users/2",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Vulnerability A (persistent)",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=3,
            raw_evidence={"dummy": 1},
        )
        self.store.record_finding(
            session_id=sess_next,
            endpoint=f"{self.target_url}/api/items/batch",
            category="Unrestricted Resource Consumption",
            status="CONFIRMED",
            evidence_notes="Vulnerability C (new)",
            verification_rule="UNRESTRICTED_RESOURCE_CONSUMPTION",
            traffic_log_id=4,
            raw_evidence={"dummy": 3},
        )

        diff = self.session_mgr.compare_sessions(sess_base, sess_next)
        self.assertNotIn("error", diff)

        counts = diff["summary_counts"]
        self.assertEqual(counts["new"], 1, f"Expected 1 new finding, got {counts['new']}")
        self.assertEqual(counts["resolved"], 1, f"Expected 1 resolved finding, got {counts['resolved']}")
        self.assertEqual(counts["persistent"], 1, f"Expected 1 persistent finding, got {counts['persistent']}")

        new_categories = [f["category"] for f in diff["new_findings"]]
        self.assertIn("Unrestricted Resource Consumption", new_categories)

        resolved_categories = [f["category"] for f in diff["resolved_findings"]]
        self.assertIn("SQL Injection", resolved_categories)

        persistent_categories = [f["category"] for f in diff["persistent_findings"]]
        self.assertIn("BOLA / IDOR", persistent_categories)


if __name__ == "__main__":
    unittest.main()
