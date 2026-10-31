"""Unit tests for OWASP ZAP Integration and Tool Registry.

Verifies:
1. ZAP REST API health checks (online and offline daemon states).
2. API key masking across receipts and representations.
3. Target URL scope enforcement on spider and active scans.
4. Spider execution, polling, and URL discovery.
5. Passive scan status monitoring.
6. Alert retrieval, normalization, and evidence database correlation.
7. Safe-by-default active scan blocking, and controlled execution when enabled.
8. Deduplication and verification gate constraints on ZAP findings.
"""

import http.server
import json
import socket
import threading
import time
import unittest
import urllib.parse
from typing import Any, Dict, List, Optional

from controller.config import AgentConfig
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.scope_validator import ScopeValidator
from controller.storage.evidence_store import EvidenceStore
from controller.tools.zap_client import ZapSecurityScanTool, mask_zap_api_key


class MockZapHttpHandler(http.server.BaseHTTPRequestHandler):
    """Mock HTTP handler simulating OWASP ZAP 2.x REST API."""

    def log_message(self, format, *args):
        # Suppress standard logging during tests
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Check API key header or query param if required by test server
        auth_key = self.headers.get("X-ZAP-API-Key") or query.get("apikey", [None])[0]
        if getattr(self.server, "require_api_key", False) and auth_key != "secret-test-key":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"code": "bad_auth", "message": "Invalid API key"}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if path.startswith("/JSON/core/view/version/"):
            data = {"version": "2.14.0"}
        elif path.startswith("/JSON/spider/action/scan/"):
            data = {"scan": "1"}
        elif path.startswith("/JSON/spider/view/status/"):
            data = {"status": "100"}
        elif path.startswith("/JSON/spider/view/results/"):
            data = {
                "results": [
                    "http://127.0.0.1:5000/api/users",
                    "http://127.0.0.1:5000/api/login",
                    "http://127.0.0.1:5000/health",
                ]
            }
        elif path.startswith("/JSON/pscan/view/recordsToScan/"):
            data = {"recordsToScan": "0"}
        elif path.startswith("/JSON/core/view/alerts/"):
            data = {
                "alerts": [
                    {
                        "id": "101",
                        "alert": "Directory Browsing",
                        "risk": "Medium",
                        "confidence": "Medium",
                        "url": "http://127.0.0.1:5000/api",
                        "method": "GET",
                        "param": "",
                        "attack": "",
                        "evidence": "Index of /",
                        "description": "Directory browsing was detected.",
                        "solution": "Disable directory indexes in web server config.",
                        "cweid": "548",
                        "wascid": "16",
                    },
                    {
                        "id": "102",
                        "alert": "X-Content-Type-Options Header Missing",
                        "risk": "Low",
                        "confidence": "High",
                        "url": "http://127.0.0.1:5000/health",
                        "method": "GET",
                        "param": "",
                        "attack": "",
                        "evidence": "",
                        "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
                        "solution": "Ensure that the application/web-server sets the Content-Type header appropriately.",
                        "cweid": "693",
                        "wascid": "15",
                    },
                ]
            }
        elif path.startswith("/JSON/ascan/action/scan/"):
            data = {"scan": "42"}
        elif path.startswith("/JSON/ascan/view/status/"):
            data = {"status": "100"}
        else:
            data = {"unknown_endpoint": path}

        self.wfile.write(json.dumps(data).encode("utf-8"))


class MockZapServer:
    """Ephemeral background mock server for ZAP REST API."""

    def __init__(self, require_api_key: bool = False):
        self.require_api_key = require_api_key
        self.server = None
        self.thread = None
        self.port = 0

    def start(self):
        # Bind to port 0 for an available ephemeral port
        self.server = http.server.HTTPServer(("127.0.0.1", 0), MockZapHttpHandler)
        self.server.require_api_key = self.require_api_key
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


class TestZapSecurityScanTool(unittest.TestCase):
    """Test suite for ZapSecurityScanTool and ZAP integration logic."""

    @classmethod
    def setUpClass(cls):
        cls.mock_zap = MockZapServer(require_api_key=False)
        cls.mock_zap.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_zap.stop()

    def setUp(self):
        self.config = AgentConfig(
            zap_base_url=self.mock_zap.base_url,
            zap_active_scan_enabled=False,
            zap_poll_interval=0.01,
            zap_max_poll_seconds=2.0,
        )
        self.tool = ZapSecurityScanTool(self.config)

    def test_zap_health_check_success(self):
        res = self.tool.execute(action="check_health")
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("connected"))
        self.assertEqual(res.get("version"), "2.14.0")
        self.assertEqual(res.get("api_key_masked"), "None")

    def test_zap_health_check_offline_daemon(self):
        # Pick an unused port
        offline_config = AgentConfig(
            zap_base_url="http://127.0.0.1:59998",
            http_connect_timeout=0.5,
        )
        offline_tool = ZapSecurityScanTool(offline_config)
        res = offline_tool.execute(action="check_health")
        self.assertFalse(res.get("success"))
        self.assertFalse(res.get("connected"))
        err_msg = res.get("error", "").lower()
        self.assertTrue(
            "unable to connect" in err_msg or "timed out" in err_msg or "refused" in err_msg,
            f"Expected connection error message, got: '{res.get('error')}'",
        )

    def test_api_key_masking(self):
        self.assertEqual(mask_zap_api_key("secret123"), "***")
        self.assertEqual(mask_zap_api_key(None), "None")
        self.assertEqual(mask_zap_api_key(""), "None")

        # When an API key is used, receipts must never reveal it
        res = self.tool.execute(action="check_health", api_key="my-super-secret-key")
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("api_key_masked"), "***")
        self.assertNotIn("my-super-secret-key", json.dumps(res))

    def test_zap_spider_out_of_scope_rejected(self):
        res = self.tool.execute(action="spider", url="http://external-malicious-target.com/api")
        self.assertFalse(res.get("success"))
        self.assertIn("out of scope", res.get("error", "").lower())

    def test_zap_spider_in_scope_and_results(self):
        res = self.tool.execute(
            action="spider",
            url="http://127.0.0.1:5000/api",
            poll_until_complete=True,
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("scan_id"), "1")
        self.assertIn("discovered_urls", res)
        self.assertIn("http://127.0.0.1:5000/api/users", res.get("discovered_urls", []))

    def test_zap_passive_scan_check(self):
        res = self.tool.execute(action="passive_scan")
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("records_remaining"), 0)
        self.assertTrue(res.get("is_drained"))

    def test_zap_get_alerts_parsing(self):
        res = self.tool.execute(action="get_alerts", url="http://127.0.0.1:5000")
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("count"), 2)
        alerts = res.get("alerts", [])
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["name"], "Directory Browsing")
        self.assertEqual(alerts[0]["risk"], "Medium")
        self.assertEqual(alerts[0]["cweid"], "548")
        self.assertEqual(alerts[1]["name"], "X-Content-Type-Options Header Missing")
        self.assertEqual(alerts[1]["risk"], "Low")

    def test_zap_active_scan_blocked_by_default(self):
        # Configuration has zap_active_scan_enabled=False
        res = self.tool.execute(action="active_scan", url="http://127.0.0.1:5000/api")
        self.assertFalse(res.get("success"))
        self.assertTrue(res.get("policy_blocked"))
        self.assertIn("disabled by safety configuration", res.get("error", ""))

    def test_zap_active_scan_allowed_when_enabled(self):
        active_cfg = AgentConfig(
            zap_base_url=self.mock_zap.base_url,
            zap_active_scan_enabled=True,
            zap_poll_interval=0.01,
            zap_max_poll_seconds=2.0,
        )
        active_tool = ZapSecurityScanTool(active_cfg)
        res = active_tool.execute(
            action="active_scan",
            url="http://127.0.0.1:5000/api",
            poll_until_complete=True,
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("scan_id"), "42")
        self.assertEqual(res.get("status"), "STARTED")

    def test_policy_engine_zap_validation(self):
        scope_validator = ScopeValidator(self.config)
        policy = PolicyEngine(
            config=self.config,
            registered_tools={"zap_scanner"},
            scope_validator=scope_validator,
        )

        # Health check approved
        dec_health = policy.evaluate_action("zap_scanner", {"action": "check_health"})
        self.assertTrue(dec_health.approved)

        # Spider on localhost approved
        dec_spider = policy.evaluate_action(
            "zap_scanner",
            {"action": "spider", "url": "http://127.0.0.1:5000/api"},
        )
        self.assertTrue(dec_spider.approved)

        # Spider on external domain rejected
        dec_out_of_scope = policy.evaluate_action(
            "zap_scanner",
            {"action": "spider", "url": "http://unauthorized-domain.com"},
        )
        self.assertFalse(dec_out_of_scope.approved)
        self.assertIn("scope violation", dec_out_of_scope.reason.lower())

        # Active scan rejected by policy when disabled
        dec_ascan = policy.evaluate_action(
            "zap_scanner",
            {"action": "active_scan", "url": "http://127.0.0.1:5000/api"},
        )
        self.assertFalse(dec_ascan.approved)
        self.assertIn("disabled by policy", dec_ascan.reason.lower())

    def test_zap_evidence_store_persistence_and_correlation(self):
        store = EvidenceStore(db_path=":memory:")
        store.create_session("sess_zap_test", "http://127.0.0.1:5000")

        # 1. Record ZAP scan
        scan_row_id = store.record_zap_scan(
            session_id="sess_zap_test",
            scan_id="scan_101",
            scan_type="spider",
            target_url="http://127.0.0.1:5000/api",
            status="COMPLETED",
            alert_count=1,
            raw_alerts=[{"alert": "Directory Browsing", "risk": "Medium"}],
        )
        self.assertGreater(scan_row_id, 0)

        # 2. Correlate alert into findings
        alert_item = {
            "name": "Directory Browsing",
            "risk": "Medium",
            "url": "http://127.0.0.1:5000/api",
            "description": "Index of directory listing found.",
            "cweid": "548",
        }
        fid, fstatus, is_new = store.correlate_and_record_zap_finding(
            session_id="sess_zap_test",
            alert=alert_item,
            zap_scan_id="scan_101",
        )
        # Must default to SUSPECTED as per safety invariant
        self.assertEqual(fstatus, "SUSPECTED")
        self.assertTrue(is_new)

        # 3. Duplicate insertion returns existing finding id (no duplicates)
        fid_dup, fstatus_dup, is_new_dup = store.correlate_and_record_zap_finding(
            session_id="sess_zap_test",
            alert=alert_item,
            zap_scan_id="scan_101",
        )
        self.assertEqual(fid, fid_dup)
        self.assertFalse(is_new_dup)

        findings = store.get_findings("sess_zap_test")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "Directory Browsing")
        self.assertEqual(findings[0]["status"], "SUSPECTED")


if __name__ == "__main__":
    unittest.main()
