"""Unit tests for Qwen model integration, JSON parser, and adapter configurations.

Verifies:
1. Multi-stage JSON extraction and relaxed parsing.
2. Safe schema validation and abstention fallbacks.
3. Checkpoint-200 and Checkpoint-300 adapter configuration and safetensors integrity.
4. 4-bit NF4 quantization hyperparameters in canonical training assets.
5. LocalQwenBrainClient environment guard (safe error when PyTorch is absent).
6. RemoteHttpQwenBrainClient REST communication, valid responses, and offline abstention.
7. Prompt formatting with Qwen ChatML markers, OpenAPI endpoints, and evidence context.
8. End-to-end feedback loop between Controller and Remote Qwen brain.
"""

import http.server
import json
import os
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from typing import Any, Dict

from controller.agent.autonomous_controller import AutonomousController
from controller.brain import (
    ModelBrainClient,
    DeterministicMockBrainClient,
    LocalQwenBrainClient,
    RemoteHttpQwenBrainClient,
    get_model_brain,
    extract_and_validate_json,
    format_classification_prompt,
    format_test_planning_prompt,
    format_action_selection_prompt,
    format_evidence_analysis_prompt,
    format_reporting_prompt,
)
from controller.config import AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.storage.evidence_store import EvidenceStore


class MockQwenHttpHandler(http.server.BaseHTTPRequestHandler):
    """Mock server simulating a GPU-hosted Qwen inference endpoint."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "status": "healthy",
                    "model": "Qwen/Qwen2.5-1.5B-Instruct",
                    "adapter": "checkpoint-200",
                    "cuda_available": True,
                    "allocated_vram_gb": 1.45,
                }).encode("utf-8")
            )
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length)
        data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if self.path == "/api/classify":
            resp = {"category": "SQL Injection", "confidence": 0.99, "reasoning": "Classic SQLi pattern"}
        elif self.path == "/api/plan":
            resp = {
                "plan_title": "Qwen Autonomous Test Plan",
                "steps": [
                    {
                        "step_number": 1,
                        "tool": "httpx_request",
                        "purpose": "Probe user list",
                        "parameters": {"url": "http://127.0.0.1:5000/api/users", "method": "GET"},
                    },
                    {
                        "step_number": 2,
                        "tool": "httpx_request",
                        "purpose": "Probe login",
                        "parameters": {"url": "http://127.0.0.1:5000/api/login", "method": "POST"},
                    },
                ],
                "rationale": "Initial reconnaissance",
            }
        elif self.path == "/api/action":
            turn = data.get("current_turn", 1)
            if turn == 1:
                resp = {
                    "action_type": "execute_tool",
                    "tool_name": "httpx_request",
                    "arguments": {"url": "http://127.0.0.1:5000/api/users", "method": "GET"},
                    "reasoning": "Executing step 1",
                }
            else:
                resp = {
                    "action_type": "complete",
                    "tool_name": "",
                    "arguments": {},
                    "reasoning": "Testing finished",
                }
        elif self.path == "/api/analyze":
            resp = {
                "status": "CONFIRMED",
                "category": "BOLA / IDOR",
                "analysis": "Unauthenticated user records disclosed",
                "verification_rule": "UNAUTHENTICATED_DATA_ACCESS",
            }
        elif self.path == "/api/report":
            resp = {"report_markdown": "# Audit Report\nIdentified BOLA / IDOR vulnerability."}
        else:
            resp = {"error": "Unknown route"}

        self.wfile.write(json.dumps(resp).encode("utf-8"))


class MockQwenServer:
    def __init__(self):
        self.server = None
        self.thread = None
        self.port = 0

    def start(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), MockQwenHttpHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2.0)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class TestQwenModelIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_server = MockQwenServer()
        cls.mock_server.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_server.stop()

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent

    # 1. Model JSON Parsing Tests
    def test_json_parsing_clean(self):
        raw = '{"action_type": "execute_tool", "tool_name": "http_request", "arguments": {"url": "http://127.0.0.1:5000"}}'
        parsed = extract_and_validate_json(raw, schema_type="action")
        self.assertEqual(parsed["action_type"], "execute_tool")
        self.assertEqual(parsed["tool_name"], "http_request")

    def test_json_parsing_fenced_markdown(self):
        raw = """Here is my decision:
```json
{
  "action_type": "complete",
  "reasoning": "Assessment goals achieved"
}
```
Please let me know if you need more."""
        parsed = extract_and_validate_json(raw, schema_type="action")
        self.assertEqual(parsed["action_type"], "complete")
        self.assertEqual(parsed["reasoning"], "Assessment goals achieved")

    def test_json_parsing_unfenced_with_filler(self):
        raw = "Based on the evidence, I observe: {\"status\": \"CONFIRMED\", \"category\": \"SQL Injection\"}. Further testing is required."
        parsed = extract_and_validate_json(raw, schema_type="analysis")
        self.assertEqual(parsed["status"], "CONFIRMED")
        self.assertEqual(parsed["category"], "SQL Injection")

    def test_json_parsing_malformed_fallback(self):
        raw = "I think the server is broken but I cannot output JSON right now."
        parsed = extract_and_validate_json(raw, schema_type="action")
        self.assertEqual(parsed["action_type"], "no_action")
        self.assertIn("error", parsed)

    # 2. Schema Validation Checks
    def test_action_schema_validation(self):
        raw = '{"tool_name": "http_request", "arguments": {"url": "http://127.0.0.1"}}'
        parsed = extract_and_validate_json(raw, schema_type="action")
        self.assertEqual(parsed["action_type"], "execute_tool")

        raw_bad = '{"action_type": "unknown_action_type"}'
        parsed_bad = extract_and_validate_json(raw_bad, schema_type="action")
        self.assertEqual(parsed_bad["action_type"], "no_action")

    def test_plan_schema_validation(self):
        raw = '{"plan_title": "My Plan", "steps": [{"step_number": 1, "tool": "http_request"}]}'
        parsed = extract_and_validate_json(raw, schema_type="plan")
        self.assertEqual(len(parsed["steps"]), 1)

        raw_no_steps = '{"plan_title": "Empty Plan"}'
        parsed_no_steps = extract_and_validate_json(raw_no_steps, schema_type="plan")
        self.assertEqual(parsed_no_steps["steps"], [])

    def test_analysis_schema_validation(self):
        raw = '{"category": "XSS"}'
        parsed = extract_and_validate_json(raw, schema_type="analysis")
        self.assertEqual(parsed["status"], "NOT_DEMONSTRATED")

    # 3. Adapter Loading Configuration Validation
    def test_adapter_configuration_integrity(self):
        adapter_dir = self.workspace_root / "staging_rebuiltv4_training_checkpoints" / "checkpoint-200"
        self.assertTrue(adapter_dir.exists(), f"Adapter dir not found at {adapter_dir}")

        config_path = adapter_dir / "adapter_config.json"
        self.assertTrue(config_path.exists(), "adapter_config.json missing")

        weights_path = adapter_dir / "adapter_model.safetensors"
        self.assertTrue(weights_path.exists(), "adapter_model.safetensors missing")
        self.assertGreater(weights_path.stat().st_size, 70 * 1024 * 1024)

        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        self.assertEqual(cfg.get("base_model_name_or_path"), "Qwen/Qwen2.5-1.5B-Instruct")
        self.assertEqual(cfg.get("peft_type"), "LORA")
        self.assertEqual(cfg.get("r"), 16)
        self.assertEqual(cfg.get("lora_alpha"), 32)
        target_mods = set(cfg.get("target_modules", []))
        expected_mods = {"q_proj", "v_proj", "k_proj", "o_proj", "gate_proj", "up_proj", "down_proj"}
        self.assertTrue(expected_mods.issubset(target_mods))

    def test_checkpoint300_adapter_configuration_integrity(self):
        adapter_dir = self.workspace_root / "staging_rebuiltv4_training_checkpoints" / "checkpoint-300"
        self.assertTrue(adapter_dir.exists())

        config_path = adapter_dir / "adapter_config.json"
        self.assertTrue(config_path.exists())

        weights_path = adapter_dir / "adapter_model.safetensors"
        self.assertTrue(weights_path.exists())
        self.assertGreater(weights_path.stat().st_size, 70 * 1024 * 1024)

    # 4. Canonical 4-Bit NF4 Quantization Configuration
    def test_quantization_hyperparameters_in_canonical_training(self):
        train_script = (
            self.workspace_root
            / "staging_rebuiltv4_training_checkpoints"
            / "training_configuration"
            / "train_rebuilt_v4.py"
        )
        self.assertTrue(train_script.exists())
        with open(train_script, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('load_in_4bit=True', content)
        self.assertIn('bnb_4bit_quant_type="nf4"', content)
        self.assertIn('bnb_4bit_use_double_quant=True', content)
        self.assertIn('Qwen/Qwen2.5-1.5B-Instruct', content)

    # 5. LocalQwenBrainClient Environment Guard
    def test_local_qwen_brain_client_safe_import_guard(self):
        # On local environment without torch installed, instantiating LocalQwenBrainClient raises clean RuntimeError
        try:
            import torch
            has_torch = True
        except ImportError:
            has_torch = False

        if not has_torch:
            with self.assertRaises(RuntimeError) as ctx:
                LocalQwenBrainClient(adapter_path=str(self.workspace_root / "staging_rebuiltv4_training_checkpoints" / "checkpoint-200"))
            self.assertIn("requires torch, transformers, and peft", str(ctx.exception))

    # 6. RemoteHttpQwenBrainClient with Mock REST Server
    def test_remote_http_qwen_brain_client(self):
        client = RemoteHttpQwenBrainClient(endpoint_url=self.mock_server.base_url)

        # Classify
        cat_res = client.classify_request({"method": "GET", "url": "/api/search?q='"})
        self.assertEqual(cat_res.get("category"), "SQL Injection")

        # Plan
        plan_res = client.create_test_plan(
            target_url="http://127.0.0.1:5000",
            endpoints=[{"path": "/api/users", "method": "GET"}],
            available_tools=[{"name": "httpx_request"}],
        )
        self.assertEqual(len(plan_res.get("steps", [])), 2)

        # Action turn 1
        action_res = client.select_next_action(
            current_turn=1,
            max_turns=5,
            plan_steps=[],
            recent_observations=[],
            available_tools=[{"name": "httpx_request"}],
        )
        self.assertEqual(action_res.get("action_type"), "execute_tool")
        self.assertEqual(action_res.get("tool_name"), "httpx_request")

        # Analyze
        analysis_res = client.analyze_evidence(
            tool_name="httpx_request",
            arguments={"url": "http://127.0.0.1:5000/api/users"},
            tool_result={"status_code": 200, "body": "[{'id': 1}]"},
        )
        self.assertEqual(analysis_res.get("status"), "CONFIRMED")
        self.assertEqual(analysis_res.get("category"), "BOLA / IDOR")

        # Report
        report_text = client.generate_report({"target": "http://127.0.0.1:5000"})
        self.assertIn("Audit Report", report_text)
        self.assertGreater(client.metrics["valid_decisions"], 0)

    # 7. Remote Client Offline Abstention
    def test_remote_http_client_offline_abstention(self):
        offline_client = RemoteHttpQwenBrainClient(
            endpoint_url="http://127.0.0.1:59997",
            timeout=0.5,
        )
        # Action proposal must cleanly abstain as no_action
        action = offline_client.select_next_action(1, 5, [], [], [{"name": "httpx_request"}])
        self.assertEqual(action.get("action_type"), "no_action")
        self.assertTrue(
            "failure" in action.get("error", "").lower()
            or "timed out" in action.get("error", "").lower()
            or "remote_inference_error" in action.get("error", "").lower(),
            f"Expected inference error message, got: {action.get('error')}",
        )
        self.assertEqual(offline_client.metrics["abstentions"], 1)

    # 8. Prompt Formatting & ChatML Tokens
    def test_prompt_formatting_and_chatml(self):
        target = "http://127.0.0.1:5000"
        endpoints = [{"path": "/api/users", "method": "GET"}]
        tools = [{"name": "httpx_request"}]

        p_plan = format_test_planning_prompt(target, endpoints, tools)
        self.assertIn("<|im_start|>system", p_plan)
        self.assertIn("<|im_start|>user", p_plan)
        self.assertIn("<|im_start|>assistant", p_plan)
        self.assertIn("Discovered Endpoints", p_plan)

        p_act = format_action_selection_prompt(1, 10, [], [], tools)
        self.assertIn("Execution Turn 1 of 10", p_act)

        p_ana = format_evidence_analysis_prompt("httpx_request", {"url": target}, {"status_code": 200})
        self.assertIn("Allowed Finding Statuses", p_ana)
        self.assertIn("CONFIRMED", p_ana)

    # 9. Factory Method Selection
    def test_get_model_brain_factory(self):
        mock_b = get_model_brain(mode="mock")
        self.assertIsInstance(mock_b, DeterministicMockBrainClient)

        remote_b = get_model_brain(mode="remote", endpoint_url="http://127.0.0.1:8000")
        self.assertIsInstance(remote_b, RemoteHttpQwenBrainClient)

        with self.assertRaises(ValueError):
            get_model_brain(mode="unsupported_mode")

    # 10. Autonomous Controller Feedback Loop with Remote Model Brain
    def test_controller_integration_with_remote_brain(self):
        client = RemoteHttpQwenBrainClient(endpoint_url=self.mock_server.base_url)
        store = EvidenceStore(db_path=":memory:")
        config = AgentConfig(max_turns=3, max_requests_per_session=10)

        controller = AutonomousController(
            config=config,
            model_brain=client,
            evidence_store=store,
        )

        res = controller.run_assessment(
            target_url="http://127.0.0.1:5000",
            endpoints=[{"path": "/api/users", "method": "GET"}],
            session_notes="Integration test with remote Qwen brain",
        )

        self.assertTrue(res.get("success"))
        self.assertGreater(res.get("turns_taken"), 0)
        self.assertIn(res.get("termination_reason"), ["Testing finished", "Finished execution loop"])
        findings = store.get_findings(res["session_id"])
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
