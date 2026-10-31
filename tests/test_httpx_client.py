"""Unit tests for HttpxRequestTool and asynchronous batch reconnaissance."""

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

from controller.config import AgentConfig
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.httpx_client import (
    HttpxRequestTool,
    execute_httpx_request,
    probe_multiple_endpoints_httpx,
)


class MockHttpxServerHandler(BaseHTTPRequestHandler):
    """Local mock HTTP handler for testing HTTPX communication."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/echo":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b'{"message": "httpx_ok", "client": "httpx"}')
        elif self.path == "/slow":
            # Sleep to trigger timeout
            time.sleep(1.5)
            self.send_response(200)
            self.end_headers()
        elif self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"H" * (60 * 1024))
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "standard"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length) if length > 0 else b""
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"action": "created", "bytes": len(data)}).encode("utf-8"))

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length) if length > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"action": "updated", "bytes": len(data)}).encode("utf-8"))

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()


class TestHttpxClient(unittest.TestCase):
    server: ClassVar[HTTPServer]
    server_thread: ClassVar[threading.Thread]
    base_url: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockHttpxServerHandler)
        port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.config = AgentConfig(http_connect_timeout=1.0, http_read_timeout=1.0)
        self.tool = HttpxRequestTool(self.config)

    def test_httpx_get_request(self):
        url = f"{self.base_url}/echo"
        res = self.tool.execute(url=url, method="GET")

        self.assertTrue(res["success"])
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["status_reason"], "OK")
        self.assertIsNotNone(res["json_body"])
        self.assertEqual(res["json_body"]["message"], "httpx_ok")
        self.assertEqual(res["client"], "httpx")
        self.assertGreater(res["elapsed_ms"], 0.0)

        # Check security header audit
        sec = res["security_headers"]
        self.assertTrue(sec["has_content_type_options"])

    def test_httpx_post_and_put_requests(self):
        # POST
        post_url = f"{self.base_url}/api/submit"
        post_res = self.tool.execute(url=post_url, method="POST", body={"test_key": "val"})
        self.assertTrue(post_res["success"])
        self.assertEqual(post_res["status_code"], 201)
        self.assertEqual(post_res["json_body"]["action"], "created")

        # PUT
        put_url = f"{self.base_url}/api/update"
        put_res = self.tool.execute(url=put_url, method="PUT", body='{"updated": true}')
        self.assertTrue(put_res["success"])
        self.assertEqual(put_res["status_code"], 200)
        self.assertEqual(put_res["json_body"]["action"], "updated")

    def test_httpx_delete_request(self):
        del_url = f"{self.base_url}/api/delete"
        res = self.tool.execute(url=del_url, method="DELETE")
        self.assertTrue(res["success"])
        self.assertEqual(res["status_code"], 204)

    def test_httpx_truncation(self):
        cfg = AgentConfig(max_response_body_bytes=512)
        tool = HttpxRequestTool(cfg)
        url = f"{self.base_url}/large"
        res = tool.execute(url=url, method="GET")

        self.assertTrue(res["success"])
        self.assertTrue(res["truncated"])
        self.assertEqual(len(res["body"].encode("utf-8")), 512)

    def test_httpx_timeout_handling(self):
        # Short timeout triggers TimeoutException
        cfg = AgentConfig(http_connect_timeout=0.2, http_read_timeout=0.2)
        tool = HttpxRequestTool(cfg)
        url = f"{self.base_url}/slow"
        res = tool.execute(url=url, method="GET")

        self.assertFalse(res["success"])
        self.assertIn("timed out", res["error"].lower())

    def test_httpx_connection_error_handling(self):
        # Port where nothing is listening
        tool = HttpxRequestTool(self.config)
        url = "http://127.0.0.1:59999/non_existent"
        res = tool.execute(url=url, method="GET")

        self.assertFalse(res["success"])
        err = res["error"].lower()
        self.assertTrue("connection error" in err or "timed out" in err or "failed" in err)

    def test_httpx_async_batch_reconnaissance(self):
        endpoints = [
            {"path": "/echo", "method": "GET"},
            {"path": "/api/users", "method": "GET"},
            {"path": "/health", "method": "GET"},
        ]

        batch_res = probe_multiple_endpoints_httpx(
            endpoints_to_probe=endpoints,
            base_url=self.base_url,
            concurrency_limit=3,
            config=self.config,
        )

        self.assertTrue(batch_res["success"])
        self.assertEqual(batch_res["total_probed"], 3)
        self.assertEqual(batch_res["successful_count"], 3)
        self.assertEqual(len(batch_res["results"]), 3)

    def test_httpx_async_batch_out_of_scope_rejection(self):
        endpoints = [
            {"path": "/test", "method": "GET"},
        ]
        # Public IP must be rejected by ScopeValidator
        batch_res = probe_multiple_endpoints_httpx(
            endpoints_to_probe=endpoints,
            base_url="http://8.8.8.8:8080",
            concurrency_limit=2,
            config=self.config,
        )
        self.assertTrue(batch_res["success"])
        self.assertEqual(batch_res["successful_count"], 0)
        self.assertIn("scope violation", batch_res["results"][0]["error"].lower())

    def test_policy_engine_httpx_authorization(self):
        engine = PolicyEngine(config=self.config, registered_tools={"httpx_request"})

        # Valid localhost request approved
        dec_ok = engine.evaluate_action("httpx_request", {"url": f"{self.base_url}/echo", "method": "GET"})
        self.assertTrue(dec_ok.approved)

        # Destructive query rejected
        dec_bad = engine.evaluate_action(
            "httpx_request",
            {"url": f"{self.base_url}/api", "method": "POST", "body": "DROP TABLE users;"},
        )
        self.assertFalse(dec_bad.approved)
        self.assertIn("destructive database operation", dec_bad.reason.lower())


if __name__ == "__main__":
    unittest.main()
