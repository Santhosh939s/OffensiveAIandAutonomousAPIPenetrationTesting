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

    # 6. Simulated Security Scenario: GraphQL Endpoint & Introspection
    def test_graphql_introspection_and_queries(self):
        # 1. Introspection query
        resp = self.client.post("/graphql", json={"query": "{ __schema { types { name } } }"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("__schema", data["data"])
        type_names = [t["name"] for t in data["data"]["__schema"]["types"]]
        self.assertIn("User", type_names)
        self.assertIn("Item", type_names)

        # 2. Query users through GraphQL
        resp2 = self.client.post("/graphql", json={"query": "{ users { id username } }"})
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertIn("users", data2["data"])
        self.assertEqual(len(data2["data"]["users"]), 3)

    # 7. Simulated Security Scenario: BOLA / IDOR Across Controlled Test Accounts (Orders)
    def test_orders_bola_idor_across_accounts(self):
        # 1. Listing orders
        resp = self.client.get("/api/orders")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data["count"], 3)

        # 2. Accessing Bob's order 102
        resp2 = self.client.get("/api/orders/102")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertEqual(data2["id"], 102)
        self.assertEqual(data2["user_id"], 2)
        self.assertIn("Bob", data2["shipping_address"])
        self.assertTrue(data2["bola_exposed"])

        # 3. Accessing Admin's order 103
        resp3 = self.client.get("/api/orders/103")
        self.assertEqual(resp3.status_code, 200)
        data3 = resp3.get_json()
        self.assertEqual(data3["id"], 103)
        self.assertEqual(data3["user_id"], 3)
        self.assertIn("Datacenter", data3["shipping_address"])

    # 8. Simulated Security Scenario: Broken Function Level Authorization (API5:2023 BFLA)
    def test_bfla_admin_function_bypass(self):
        # Unprivileged caller invokes admin role modification on user 1
        resp = self.client.post("/api/admin/users/1/role", json={"role": "admin"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["bfla_exposed"])
        self.assertEqual(data["new_role"], "admin")

        # Unprivileged caller retrieves administrative export
        resp2 = self.client.get("/api/admin/export")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertTrue(data2["bfla_exposed"])
        self.assertGreaterEqual(data2["users_count"], 3)
        self.assertIn("audit_logs", data2)

    # 9. Simulated Security Scenario: Unrestricted Business Flow (API6:2023)
    def test_business_flow_coupon_stacking_abuse(self):
        # Repeatedly apply coupon without rate limit or quota enforcement
        for i in range(3):
            resp = self.client.post("/api/coupons/apply", json={"coupon_code": "SAVE50", "order_id": 101})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertTrue(data["business_flow_abuse"])
            self.assertEqual(data["times_applied"], i + 1)

    # 10. Simulated Security Scenario: Improper Inventory Management (API9:2023)
    def test_shadow_and_deprecated_api_inventory(self):
        # Legacy v1 user export accessible without authentication
        resp = self.client.get("/api/v1/users/export")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["shadow_api"])
        self.assertEqual(data["version"], "v1.0-deprecated")
        self.assertGreaterEqual(len(data["unredacted_records"]), 3)

        # Legacy debug dump accessible
        resp2 = self.client.get("/api/v1/debug/dump")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertTrue(data2["shadow_api"])
        self.assertTrue(data2["debug_mode"])

    # 11. Simulated Security Scenario: Unsafe Consumption of APIs (API10:2023)
    def test_unsafe_api_consumption_webhook(self):
        resp = self.client.post("/api/integrations/webhook", json={
            "partner_name": "third_party_gateway",
            "callback_url": "http://127.0.0.1:5000/api/items",
            "event": "funds_transferred",
            "payload": {"amount": 5000, "currency": "USD"},
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["unsafe_consumption"])
        self.assertFalse(data["signature_verified"])
        self.assertEqual(data["downstream_status"], "trusted_without_verification")


if __name__ == "__main__":
    unittest.main()

