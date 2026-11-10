"""Unit tests for API Inventory Scanner Tool (OWASP API9:2023)."""

import threading
import time
import unittest
from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from controller.tools.inventory_scanner import ApiInventoryScannerTool
from controller.config import AgentConfig


class TestApiInventoryScannerTool(unittest.TestCase):
    """Test suite for discovering shadow, legacy, and undocumented API endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.db = LabDatabase(":memory:")
        cls.app = create_app(cls.db)
        cls.server = make_server("127.0.0.1", 0, cls.app)
        cls.port = cls.server.server_port
        cls.target_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()

    def setUp(self):
        self.config = AgentConfig(allowed_hosts={"127.0.0.1", "localhost"})
        self.tool = ApiInventoryScannerTool(self.config)

    def test_shadow_endpoint_discovery_on_lab(self):
        """Verify tool detects legacy v1 shadow export and debug endpoints."""
        res = self.tool.execute(
            target_url=self.target_url,
            candidate_paths=["/api/v1/users/export", "/api/v1/debug/dump", "/api/nonexistent/route"],
            known_endpoints=["/api/users", "/api/items"],
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["paths_tested"], 3)
        self.assertEqual(res["shadow_count"], 2)

        paths_found = [ep["path"] for ep in res["shadow_endpoints_found"]]
        self.assertIn("/api/v1/users/export", paths_found)
        self.assertIn("/api/v1/debug/dump", paths_found)

        # Check findings
        self.assertGreaterEqual(len(res["findings"]), 2)
        rules = [f["verification_rule"] for f in res["findings"]]
        self.assertIn("SHADOW_OR_DEPRECATED_API_EXPOSED", rules)

        # Check traffic logs recorded
        self.assertEqual(len(res["traffic_interactions"]), 3)

    def test_out_of_scope_rejection(self):
        """Verify inventory tool respects scope boundaries and rejects public domains."""
        res = self.tool.execute(target_url="http://public-target.com")
        self.assertFalse(res["success"])
        self.assertIn("rejected by scope policy", res["error"])
        self.assertEqual(len(res["shadow_endpoints_found"]), 0)


if __name__ == "__main__":
    unittest.main()

