"""Unit tests for OpenApiParserTool (OpenAPI 3.x and Swagger 2.0 discovery)."""

import json
import os
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

from controller.config import AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.openapi_parser import OpenApiParserTool


class MockSpecServerHandler(BaseHTTPRequestHandler):
    """Local mock HTTP handler serving test OpenAPI specs."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Live Mock API", "version": "1.2.3"},
                "servers": [{"url": "http://127.0.0.1:5000"}],
                "paths": {
                    "/api/items": {
                        "get": {"summary": "List items", "responses": {"200": {"description": "OK"}}}
                    }
                },
            }
            self.wfile.write(json.dumps(spec).encode("utf-8"))
        elif self.path == "/404":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()


class TestOpenApiParserTool(unittest.TestCase):
    server: ClassVar[HTTPServer]
    server_thread: ClassVar[threading.Thread]
    base_url: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockSpecServerHandler)
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
        self.workspace_root = Path(__file__).resolve().parent.parent
        self.tool = OpenApiParserTool()

    def test_parse_openapi3_json_file(self):
        spec_path = str(self.workspace_root / "lab" / "openapi_spec.json")
        res = self.tool.execute(spec_source=spec_path)

        self.assertTrue(res["success"], f"Failed to parse JSON spec: {res.get('error')}")
        self.assertEqual(res["title"], "Local Vulnerable API Laboratory")
        self.assertEqual(res["version"], "1.0.0")
        self.assertTrue(res["spec_version"].startswith("3."))
        self.assertGreaterEqual(res["endpoints_count"], 6)

        # Verify specific endpoint extraction
        paths = [ep["path"] for ep in res["endpoints"]]
        self.assertIn("/health", paths)
        self.assertIn("/api/users", paths)
        self.assertIn("/api/users/{id}", paths)
        self.assertIn("/api/search", paths)

        # Check parameter extraction on /api/users/{id}
        user_id_ep = next(ep for ep in res["endpoints"] if ep["path"] == "/api/users/{id}" and ep["method"] == "GET")
        self.assertEqual(len(user_id_ep["path_parameters"]), 1)
        self.assertEqual(user_id_ep["path_parameters"][0]["name"], "id")

        # Check planning endpoints format
        self.assertGreaterEqual(len(res["planning_endpoints"]), 6)
        first_plan = res["planning_endpoints"][0]
        self.assertIn("path", first_plan)
        self.assertIn("method", first_plan)
        self.assertIn("parameters", first_plan)

    def test_parse_openapi3_yaml_file(self):
        spec_path = str(self.workspace_root / "lab" / "openapi_spec.yaml")
        res = self.tool.execute(spec_source=spec_path)

        self.assertTrue(res["success"])
        self.assertEqual(res["title"], "Local Vulnerable API Laboratory")
        self.assertIn("BearerAuth", res["security_schemes"])
        self.assertEqual(res["security_schemes"]["BearerAuth"]["type"], "http")

    def test_parse_live_url(self):
        url = f"{self.base_url}/openapi.json"
        res = self.tool.execute(spec_source=url)

        self.assertTrue(res["success"])
        self.assertEqual(res["title"], "Live Mock API")
        self.assertEqual(res["endpoints_count"], 1)

    def test_parse_swagger2_json_content(self):
        swagger2_doc = {
            "swagger": "2.0",
            "info": {"title": "Legacy Swagger 2 API", "version": "2.0.1"},
            "host": "127.0.0.1:8080",
            "basePath": "/v2",
            "schemes": ["http"],
            "securityDefinitions": {
                "ApiKeyAuth": {"type": "apiKey", "name": "X-API-KEY", "in": "header"}
            },
            "paths": {
                "/products": {
                    "get": {
                        "summary": "Get products",
                        "parameters": [
                            {"name": "category", "in": "query", "type": "string", "required": False}
                        ],
                        "responses": {"200": {"description": "Product list"}},
                    },
                    "post": {
                        "summary": "Create product",
                        "parameters": [
                            {"name": "body", "in": "body", "required": True, "schema": {"type": "object"}}
                        ],
                        "responses": {"201": {"description": "Created"}},
                    },
                }
            },
        }

        res = self.tool.execute(spec_content=json.dumps(swagger2_doc))
        self.assertTrue(res["success"])
        self.assertEqual(res["title"], "Legacy Swagger 2 API")
        self.assertEqual(res["spec_version"], "2.0")
        self.assertEqual(res["endpoints_count"], 2)
        self.assertIn("ApiKeyAuth", res["security_schemes"])

    def test_invalid_specifications(self):
        # 1. Empty content
        res1 = self.tool.execute(spec_content="")
        self.assertFalse(res1["success"])
        self.assertIn("Either 'spec_source'", res1["error"])

        # 2. Corrupted YAML/JSON
        res2 = self.tool.execute(spec_content="key: [unclosed list")
        self.assertFalse(res2["success"])
        self.assertIn("Failed to parse", res2["error"])

        # 3. Valid JSON but not an OpenAPI/Swagger spec
        res3 = self.tool.execute(spec_content='{"random_key": "random_value"}')
        self.assertFalse(res3["success"])
        self.assertIn("Unsupported specification format", res3["error"])

        # 4. Non-existent file
        res4 = self.tool.execute(spec_source="non_existent_file_path.json")
        self.assertFalse(res4["success"])
        self.assertIn("file not found", res4["error"].lower())

    def test_scope_validation_on_spec_url(self):
        # External URL must be rejected by ScopeValidator
        external_url = "http://external-public-site.com/swagger.json"
        res = self.tool.execute(spec_source=external_url)
        self.assertFalse(res["success"])
        self.assertIn("scope violation", res["error"].lower())


if __name__ == "__main__":
    unittest.main()

