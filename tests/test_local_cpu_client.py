"""Unit and Integration Tests for Local CPU Brain Client (8 GB RAM Offline Deployment)."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from controller.agent.autonomous_controller import AutonomousController
from controller.brain.local_cpu_client import (
    LocalCpuBrainClient,
    find_default_gguf_model,
)
from controller.brain.model_gateway import get_model_brain
from controller.config import AgentConfig
from controller.storage.evidence_store import EvidenceStore


class TestLocalCpuBrainClient(unittest.TestCase):
    """Test suite verifying LocalCpuBrainClient memory limits, prompts, and inference logic."""

    def setUp(self):
        self.store = EvidenceStore(":memory:")

    def tearDown(self):
        if self.store._shared_conn:
            self.store._shared_conn.close()

    def test_initialization_with_mock_fallback(self):
        """Verify client initializes in fallback mode when no GGUF file is present."""
        client = LocalCpuBrainClient(model_path="/nonexistent/model.gguf", allow_mock_fallback=True)
        self.assertEqual(client.engine, "mock_fallback")
        self.assertLessEqual(client.n_ctx, 4096)
        self.assertGreaterEqual(client.n_threads, 1)
        self.assertTrue(client.use_mmap)
        self.assertIn("peak_ram_mb", client.metrics)

    def test_initialization_strict_raises_when_missing(self):
        """Verify client raises FileNotFoundError when allow_mock_fallback=False and file missing."""
        with self.assertRaises(FileNotFoundError):
            LocalCpuBrainClient(model_path="/nonexistent/model.gguf", allow_mock_fallback=False)

    def test_find_default_gguf_model_with_env(self):
        """Verify find_default_gguf_model respects QWEN_CPU_GGUF_PATH."""
        # When env points to a valid file
        test_file = os.path.abspath(__file__)
        with patch.dict(os.environ, {"QWEN_CPU_GGUF_PATH": test_file}):
            found = find_default_gguf_model()
            self.assertEqual(found, test_file)

    def test_classify_request(self):
        """Verify request classification runs and updates metrics."""
        client = LocalCpuBrainClient(allow_mock_fallback=True)
        res = client.classify_request({"path": "/api/users", "query": "id=1' OR 1=1--"})
        self.assertIn("category", res)
        self.assertEqual(res["category"], "SQL Injection")
        self.assertGreaterEqual(client.metrics["total_inferences"], 1)
        self.assertGreaterEqual(client.metrics["valid_decisions"], 1)

    def test_create_test_plan(self):
        """Verify autonomous test plan generation returns structured steps."""
        client = LocalCpuBrainClient(allow_mock_fallback=True)
        endpoints = [
            {"path": "/api/search", "method": "GET", "parameters": [{"name": "q"}]},
            {"path": "/api/users/{id}", "method": "GET", "parameters": [{"name": "id"}]},
        ]
        tools = [{"name": "httpx_request"}]
        plan = client.create_test_plan("http://127.0.0.1:5050", endpoints, tools)
        self.assertIn("steps", plan)
        self.assertGreater(len(plan["steps"]), 0)
        self.assertIn("plan_title", plan)

    def test_select_next_action_abstention(self):
        """Verify safe abstention when turn budget is exceeded or complete."""
        client = LocalCpuBrainClient(allow_mock_fallback=True)
        action = client.select_next_action(
            current_turn=11,
            max_turns=10,
            plan_steps=[],
            recent_observations=[],
            available_tools=[{"name": "httpx_request"}],
        )
        self.assertEqual(action.get("action_type"), "complete")
        self.assertGreaterEqual(client.metrics["abstentions"], 1)

    def test_analyze_evidence_verification_rules(self):
        """Verify strict verification rule attachment on evidence analysis."""
        client = LocalCpuBrainClient(allow_mock_fallback=True)

        # 1. SQL Injection Error
        res_sqli = client.analyze_evidence(
            tool_name="httpx_request",
            arguments={"url": "http://127.0.0.1:5050/api/search?q='", "method": "GET"},
            tool_result={
                "status_code": 500,
                "body": json.dumps({"error": "unrecognized token near '''", "syntax error": True}),
            },
        )
        self.assertEqual(res_sqli.get("status"), "CONFIRMED")
        self.assertEqual(res_sqli.get("verification_rule"), "SQL_SYNTAX_ERROR_MATCH")

        # 2. Privilege Escalation
        res_priv = client.analyze_evidence(
            tool_name="httpx_request",
            arguments={"url": "http://127.0.0.1:5050/api/users/2", "method": "PUT", "body": '{"role": "admin", "is_admin": 1}'},
            tool_result={
                "status_code": 200,
                "body": json.dumps({"message": "Profile updated", "role": "admin", "is_admin": 1}),
            },
        )
        self.assertEqual(res_priv.get("status"), "CONFIRMED")
        self.assertEqual(res_priv.get("verification_rule"), "ROLE_ELEVATION_VERIFIED")

        # 3. JWT None Algorithm
        res_jwt = client.analyze_evidence(
            tool_name="jwt_inspector",
            arguments={"token": "eyJhbGciOiJub25lIn0.e30."},
            tool_result={
                "extracted_fields": {"algorithm": "none", "subject": "admin"},
            },
        )
        self.assertEqual(res_jwt.get("status"), "CONFIRMED")
        self.assertEqual(res_jwt.get("verification_rule"), "TOKEN_ALGORITHM_NONE_ACCEPTED")

    def test_mock_llama_cpp_runtime_inference(self):
        """Verify behavior when llama-cpp-python is simulated."""
        client = LocalCpuBrainClient(allow_mock_fallback=True)
        # Manually wire a mock llama instance
        client.engine = "llama_cpp"
        mock_llm = MagicMock()
        mock_llm.return_value = {
            "choices": [{"text": '```json\n{"category": "XSS", "confidence": 0.95, "reasoning": "Injected script"}\n```'}],
            "usage": {"prompt_tokens": 40, "completion_tokens": 15},
        }
        client._llm = mock_llm

        res = client.classify_request({"path": "/api/profile", "query": "name=<script>alert(1)</script>"})
        self.assertEqual(res.get("category"), "XSS")
        self.assertGreaterEqual(client.metrics["total_prompt_tokens"], 40)
        self.assertGreaterEqual(client.metrics["total_completion_tokens"], 15)
        self.assertGreaterEqual(client.metrics["valid_decisions"], 1)

    def test_gateway_factory_integration(self):
        """Verify get_model_brain(mode='local_cpu') retrieves LocalCpuBrainClient."""
        brain = get_model_brain(mode="local_cpu", reuse_instance=False)
        self.assertIsInstance(brain, LocalCpuBrainClient)
        self.assertIn(brain.metrics["engine"], {"llama_cpp", "llama_cli", "mock_fallback"})

    def test_controller_integration_with_local_cpu_brain(self):
        """Verify AutonomousController runs turns smoothly using LocalCpuBrainClient."""
        config = AgentConfig(
            max_turns=2,
            max_requests_per_session=5,
            max_model_calls=5,
            allowed_hosts={"127.0.0.1", "localhost"},
            db_path=":memory:",
        )
        brain = LocalCpuBrainClient(model_path="/dummy/path.gguf", allow_mock_fallback=True)
        controller = AutonomousController(
            config=config,
            model_brain=brain,
            evidence_store=self.store,
        )

        res = controller.run_assessment(
            target_url="http://127.0.0.1:5050",
            endpoints=[{"path": "/api/users", "method": "GET"}],
            session_notes="Local CPU client integration test",
        )
        self.assertTrue(res["success"])
        self.assertIsNotNone(res["session_id"])
        self.assertGreater(res["turns_taken"], 0)
        self.assertGreaterEqual(brain.metrics["total_inferences"], 1)


if __name__ == "__main__":
    unittest.main()
