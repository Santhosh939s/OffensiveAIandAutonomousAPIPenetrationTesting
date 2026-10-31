"""Unit tests for the intentionally vulnerable Local API Security Laboratory."""

import json
import unittest

from lab.app import create_app
from lab.database import LabDatabase
from lab.seed_data import seed_database


class TestLocalApiLab(unittest.TestCase):
    def setUp(self):
        # Create an isolated in-memory test database and test client for each test case
        self.db = LabDatabase(":memory:")
        self.app = create_app(self.db)
        self.client = self.app.test_client()

    # 1. Normal Endpoint Behaviour Tests
    def test_health_check(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["binding"], "127.0.0.1")

    def test_user_listing(self):
        resp = self.client.get("/api/users")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 3)
        self.assertEqual(data["users"][0]["username"], "alice")

    def test_item_listing(self):
        resp = self.client.get("/api/items")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data["count"], 5)

    # 2. Simulated Security Scenario: BOLA / IDOR
    def test_bola_idor_leakage(self):
        # Alice requests Bob's user ID (2)
        resp = self.client.get("/api/users/2")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        # Verifies sensitive fields are exposed without authorization
        self.assertEqual(data["username"], "bob")
        self.assertIn("password_hash", data)
        self.assertIn("api_token", data)
        self.assertEqual(data["api_token"], "tok_bob_live_47219")

    # 3. Simulated Security Scenario: Weak Auth & 'none' JWT
    def test_authentication_bypass_and_none_jwt(self):
        # Admin login with empty password bypass
        resp = self.client.post(
            "/api/login",
            json={"username": "admin", "password": ""},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        token = data["token"]
        self.assertIsNotNone(token)

        # Inspect token header structure for alg="none"
        header_b64 = token.split(".")[0]
        # Add padding
        header_b64 += "=" * ((4 - len(header_b64) % 4) % 4)
        import base64
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
        self.assertEqual(header.get("alg"), "none")

    # 4. Simulated Security Scenario: Mass Assignment
    def test_mass_assignment_privilege_escalation(self):
        # Normal user 1 (Alice) sends a profile update requesting admin role
        resp = self.client.put(
            "/api/users/1",
            json={"role": "admin", "is_admin": 1},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["role"], "admin")
        self.assertEqual(data["user"]["is_admin"], 1)

    # 5. Simulated Security Scenario: Unsafe Input Handling / SQL Syntax Anomaly
    def test_unsafe_search_sql_syntax_error(self):
        # Clean search returns 200
        clean_resp = self.client.get("/api/search?q=laptop")
        self.assertEqual(clean_resp.status_code, 200)

        # Injected single quote triggers unhandled SQL syntax error returning 500
        probe_resp = self.client.get("/api/search?q='")
        self.assertEqual(probe_resp.status_code, 500)
        err_data = probe_resp.get_json()
        self.assertIn("error", err_data)
        self.assertIn("syntax error", err_data["error"].lower())


if __name__ == "__main__":
    unittest.main()

