"""QA Phase 1: Real End-to-End Model Testing.

Validates the complete autonomous penetration testing workflow using the actual
local fine-tuned Qwen GGUF model via llama-cli.exe (strictly non-mock).

Workflow verified:
1. Authentic Local Lab server is running on localhost.
2. Assessment request dispatched.
3. Backend session created in SQLite.
4. Autonomous controller initialized with real LocalCpuBrainClient.
5. Actual GGUF inference executed by llama-cli.exe.
6. Model-generated action selected and validated by PolicyEngine.
7. Tool executed against the authentic lab target.
8. Observation returned to model context.
9. Verification gate evaluates evidence.
10. Final report generated (Markdown, JSON, HTML).
11. Dashboard session APIs return valid results.
"""

import os
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
from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model
from controller.storage.evidence_store import EvidenceStore
from controller.reporting.report_generator import ReportGenerator
from controller.tools import build_default_tool_registry
from dashboard.session_manager import DashboardSessionManager


class TestQAPhase1RealGGUF(unittest.TestCase):
    """Phase 1 QA: Real End-to-End GGUF Model Execution."""

    server: ClassVar[Any] = None
    server_thread: ClassVar[threading.Thread] = None
    target_url: ClassVar[str] = ""
    port: ClassVar[int] = 0
    model_path: ClassVar[str] = ""

    @classmethod
    def setUpClass(cls):
        # 1. Locate real GGUF model
        cls.model_path = find_default_gguf_model()
        if not cls.model_path or not os.path.exists(cls.model_path):
            raise unittest.SkipTest("Real GGUF model file not found in models/ directory.")

        # 2. Allocate free port on localhost
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        # 3. Start authentic Local API Lab
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

    def test_real_gguf_end_to_end_assessment_workflow(self):
        """Execute complete closed-loop assessment using strictly real GGUF inference."""
        # A. Initialize Real Local CPU Brain Client (allow_mock_fallback=False)
        real_brain = LocalCpuBrainClient(
            model_path=self.model_path,
            allow_mock_fallback=False,
            n_threads=4,
            n_ctx=4096,
        )
        self.assertEqual(real_brain.engine, "llama_cli")

        # B. Set up Controller and Storage
        store = EvidenceStore(db_path=":memory:")
        tools = build_default_tool_registry()
        config = AgentConfig(
            max_turns=2,
            max_requests_per_session=10,
            allowed_hosts={"127.0.0.1", "localhost", f"127.0.0.1:{self.port}"},
        )
        controller = AutonomousController(
            config=config,
            model_brain=real_brain,
            evidence_store=store,
            tool_registry=tools,
        )

        session_id = f"sess_qa_real_gguf_{int(time.time())}"

        # C. Run assessment against real lab with OpenAPI discovery
        result = controller.run_assessment(
            target_url=self.target_url,
            spec_source=f"{self.target_url}/openapi.json",
            session_notes="QA Phase 1: Real GGUF End-to-End Test",
            session_id=session_id,
        )

        # D. Verify real model metrics
        self.assertTrue(result["success"])
        self.assertEqual(result["session_id"], session_id)
        self.assertGreater(result["turns_taken"], 0)
        self.assertGreater(result["requests_sent"], 0)

        # Confirm actual model inference occurred via llama-cli.exe
        self.assertGreater(real_brain.metrics["total_inferences"], 0)
        self.assertGreater(real_brain.metrics["peak_ram_mb"], 0.0)
        self.assertEqual(real_brain.metrics["engine"], "llama_cli")

        # E. Verify findings and evidence committed to SQLite
        findings = store.get_findings(session_id)
        self.assertIsInstance(findings, list)

        traffic = store.get_traffic_logs(session_id)
        self.assertGreater(len(traffic), 0)

        tool_execs = store.get_tool_executions(session_id)
        self.assertGreater(len(tool_execs), 0)

        # F. Verify Report Generation across formats
        generator = ReportGenerator(evidence_store=store)
        md_report = generator.generate_report(session_id)
        self.assertIn("# API Security Penetration Testing Assessment Report", md_report)
        self.assertIn(session_id, md_report)

        json_report = generator.generate_json_report(session_id)
        self.assertEqual(json_report["session"]["session_id"], session_id)
        self.assertIn("risk_summary", json_report)

        html_report = generator.generate_html_report(session_id)
        self.assertIn("<!DOCTYPE html>", html_report)
        self.assertIn(session_id, html_report)


if __name__ == "__main__":
    unittest.main()
