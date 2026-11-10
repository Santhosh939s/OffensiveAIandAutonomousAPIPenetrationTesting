"""Unit tests for Business Flow Probe Tool (OWASP API6:2023)."""

import threading
import time
import unittest
from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from controller.tools.business_flow_probe import BusinessFlowProbeTool
from controller.config import AgentConfig


class TestBusinessFlowProbeTool(unittest.TestCase):
    """Test suite for detecting unrestricted access to sensitive business flows."""

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
        self.tool = BusinessFlowProbeTool(self.config)

    def test_coupon_business_flow_probe_detection(self):
        """Verify tool detects unrestricted repeated execution of coupon discount flow."""
        res = self.tool.execute(
            url=f"{self.target_url}/api/coupons/apply",
            method="POST",
            payload={"coupon_code": "SAVE50", "order_id": 101},
            iterations=3,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["iterations_executed"], 3)
        self.assertTrue(res["all_succeeded"])
        self.assertGreaterEqual(len(res["findings"]), 1)

        finding = res["findings"][0]
        self.assertEqual(finding["type"], "BUSINESS_FLOW_UNRESTRICTED_ACCESS")
        self.assertEqual(finding["verification_rule"], "BUSINESS_FLOW_UNRESTRICTED_ACCESS")
        self.assertIn("consecutive times without rate limiting", finding["evidence_notes"])

        # Check traffic logged
        self.assertEqual(len(res["traffic_interactions"]), 3)

    def test_out_of_scope_rejection(self):
        """Verify business flow probe tool rejects external targets."""
        res = self.tool.execute(url="https://external-ecommerce-site.com/api/checkout")
        self.assertFalse(res["success"])
        self.assertIn("rejected by scope policy", res["error"])
        self.assertEqual(res["iterations_completed"], 0)


if __name__ == "__main__":
    unittest.main()

