"""Unit tests for tool implementations (http_request, jwt_inspector, parameter_fuzzer)."""

import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

from controller.config import AgentConfig
from controller.tools.registry import BaseTool, ToolRegistry
from controller.tools.http_request import execute_http_request, HttpRequestTool
from controller.tools.jwt_inspector import inspect_jwt, extract_jwt_token, JwtInspectorTool
from controller.tools.parameter_fuzzer import probe_api_parameters, ParameterFuzzerTool


class MockLocalServerHandler(BaseHTTPRequestHandler):
    """Simple in-process HTTP handler for testing tool interactions safely."""

    def log_message(self, format, *args):
        # Suppress server logging during unit tests
        pass

    def do_GET(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/dest")
            self.end_headers()
        elif self.path.startswith("/large"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            # Send 60KB of data
            self.wfile.write(b"A" * (60 * 1024))
        elif self.path.startswith("/echo"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "message": "hello world"}')
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_data = {"status": "created", "received_len": len(body)}
        self.wfile.write(json.dumps(response_data).encode("utf-8"))


class TestTools(unittest.TestCase):
    server: ClassVar[HTTPServer]
    server_thread: ClassVar[threading.Thread]
    base_url: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        # Start local mock server on an ephemeral port on 127.0.0.1
        cls.server = HTTPServer(("127.0.0.1", 0), MockLocalServerHandler)
        port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # --- HTTP Request Tool Tests ---

    def test_http_request_get(self):
        url = f"{self.base_url}/echo"
        res = execute_http_request(url=url, method="GET")
        self.assertTrue(res["success"])
        self.assertEqual(res["status_code"], 200)
        self.assertIn("hello world", res["body"])
        self.assertFalse(res["truncated"])

    def test_http_request_post(self):
        url = f"{self.base_url}/submit"
        payload = json.dumps({"test_key": "test_value"})
        res = execute_http_request(url=url, method="POST", body=payload)
        self.assertTrue(res["success"])
        self.assertEqual(res["status_code"], 201)
        self.assertIn("received_len", res["body"])

    def test_http_request_truncation(self):
        config = AgentConfig(max_response_body_bytes=1024)  # 1 KB limit
        url = f"{self.base_url}/large"
        res = execute_http_request(url=url, method="GET", config=config)
        self.assertTrue(res["success"])
        self.assertTrue(res["truncated"])
        self.assertLessEqual(len(res["body"].encode("utf-8")), 1024)

    def test_http_request_disabled_redirect(self):
        url = f"{self.base_url}/redirect"
        res = execute_http_request(url=url, method="GET")
        self.assertTrue(res["success"])
        # Should stop at 302 without following redirect
        self.assertEqual(res["status_code"], 302)

    # --- JWT Inspector Tool Tests ---

    def _create_jwt(self, header: dict, payload: dict, signature: str = "dummysig") -> str:
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{h_b64}.{p_b64}.{signature}"

    def test_jwt_inspector_valid_token(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user_12345",
            "roles": ["admin", "tester"],
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = self._create_jwt(header, payload)

        res = inspect_jwt(token)
        self.assertTrue(res["success"])
        self.assertFalse(res["signature_verified"])
        self.assertIn("DECODED ONLY", res["verification_disclaimer"])
        self.assertEqual(res["extracted_fields"]["algorithm"], "HS256")
        self.assertEqual(res["extracted_fields"]["subject"], "user_12345")
        self.assertIn("admin", res["extracted_fields"]["roles_or_scopes"])
        self.assertFalse(res["extracted_fields"]["is_expired"])

    def test_jwt_inspector_none_alg_and_expired(self):
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "guest",
            "exp": int(time.time()) - 1000,  # Expired
        }
        token = self._create_jwt(header, payload)

        res = inspect_jwt(token)
        self.assertTrue(res["success"])
        self.assertEqual(res["extracted_fields"]["algorithm"], "none")
        self.assertTrue(res["extracted_fields"]["is_expired"])
        # Check security observations detected
        obs_text = " ".join(res["security_observations"]).lower()
        self.assertIn("algorithm is set to 'none'", obs_text)
        self.assertIn("expired", obs_text)

    def test_jwt_inspector_malformed(self):
        res = inspect_jwt("not-a-jwt")
        self.assertFalse(res["success"])
        self.assertIn("Invalid JWT structure", res["error"])

    # --- Parameter Fuzzer Tool Tests ---

    def test_parameter_fuzzer(self):
        url = f"{self.base_url}/search"
        res = probe_api_parameters(
            url=url,
            method="GET",
            parameters={"query": "initial_term"},
            probes_to_run=["empty_string", "integer_zero"],
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["probes_executed"], 2)
        self.assertEqual(len(res["results"]), 2)
        self.assertEqual(res["results"][0]["parameter"], "query")

    def test_http_request_json_parsing_and_security_headers(self):
        url = f"{self.base_url}/echo"
        res = execute_http_request(url=url, method="GET")
        self.assertTrue(res["success"])
        self.assertIsNotNone(res["json_body"])
        self.assertEqual(res["json_body"]["status"], "ok")
        self.assertIn("security_headers", res)
        self.assertIn("missing", res["security_headers"])

    def test_jwt_inspector_bearer_prefix_and_flaw_indicators(self):
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "iat": int(time.time())}
        raw_token = self._create_jwt(header, payload)
        bearer_token = f"Bearer {raw_token}"

        res = inspect_jwt(bearer_token)
        self.assertTrue(res["success"])
        self.assertEqual(res["extracted_fields"]["algorithm"], "none")
        self.assertGreater(len(res["flaw_indicators"]), 0)
        types = [f["type"] for f in res["flaw_indicators"]]
        self.assertIn("NONE_ALGORITHM", types)

    def test_parameter_fuzzer_json_mode(self):
        url = f"{self.base_url}/submit"
        res = probe_api_parameters(
            url=url,
            method="POST",
            json_body={"username": "alice", "score": 100},
            probes_to_run=["empty_string", "null_literal"],
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["mode"], "json")
        self.assertEqual(res["probes_executed"], 4)
        self.assertGreater(len(res["sub_requests"]), 0)

    def test_tool_registry_base_tool_interface(self):
        registry = ToolRegistry()
        http_tool = HttpRequestTool()
        jwt_tool = JwtInspectorTool()
        fuzzer_tool = ParameterFuzzerTool()

        registry.register_tool(http_tool)
        registry.register_tool(jwt_tool)
        registry.register_tool(fuzzer_tool)

        self.assertEqual(len(registry.list_tool_names()), 3)
        self.assertTrue(registry.has_tool("http_request"))
        self.assertTrue(registry.has_tool("jwt_inspector"))
        self.assertTrue(registry.has_tool("parameter_fuzzer"))

        # Test execute via registry
        res = registry.execute("jwt_inspector", {"token": "invalid"})
        self.assertFalse(res["success"])
        self.assertEqual(res["tool_name"], "jwt_inspector")


if __name__ == "__main__":
    unittest.main()
