"""Integration and Security Tests for Dashboard Authentication & Role Gating.

Covers:
11. CSRF enforcement on state-changing administrative endpoints
12. Role separation (Admin vs Operator vs Auditor vs Unauthenticated)
13. Direct API authentication bypass attempts
14. Preservation of existing assessment endpoints
15. Database preservation and non-destructive schema extension
"""

import json
import os
import unittest

from controller.auth.authentication_service import AuthenticationService
from controller.auth.role_service import Role
from controller.auth.session_service import SessionService
from controller.storage.evidence_store import EvidenceStore
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager


class TestDashboardAuthentication(unittest.TestCase):
    """Integration test suite for Dashboard authentication, session security, and role boundaries."""

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(self.store)
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,
        )
        self.manager = DashboardSessionManager(db_path=":memory:", store=self.store)
        self.app = create_dashboard_app(
            session_manager=self.manager,
            auth_service=self.auth_service,
            session_service=self.session_service,
        )
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Seed roles for testing
        self.admin = self.auth_service.bootstrap_admin("admin_alice", "AdminPass123!")
        self.operator = self.auth_service.create_user(
            username="operator_bob",
            password="OperatorPass123!",
            role=Role.OPERATOR.value,
        )
        self.auditor = self.auth_service.create_user(
            username="auditor_charlie",
            password="AuditorPass123!",
            role=Role.AUDITOR.value,
        )

    def tearDown(self):
        self.store.close()

    def _login(self, username, password):
        """Helper to log in and return (raw_token, csrf_token)."""
        resp = self.client.post(
            "/api/auth/login",
            data=json.dumps({"username": username, "password": password}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200, f"Login failed for {username}: {resp.get_data(as_text=True)}")
        data = resp.get_json()
        csrf_token = data["csrf_token"]
        raw_token = resp.headers.get("Set-Cookie").split("session_token=")[1].split(";")[0]
        return raw_token, csrf_token

    # -------------------------------------------------------------------------
    # 1. Login Endpoint & Cookie Properties
    # -------------------------------------------------------------------------
    def test_login_success_and_cookie_security_attributes(self):
        """Verify successful login sets HttpOnly, SameSite=Strict cookie."""
        resp = self.client.post(
            "/api/auth/login",
            data=json.dumps({"username": "admin_alice", "password": "AdminPass123!"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("csrf_token", data)
        self.assertEqual(data["user"]["role"], "admin")

        set_cookie = resp.headers.get("Set-Cookie")
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.assertIn("Path=/", set_cookie)

    def test_login_failure_generic_message(self):
        """Verify failed login returns 401 with generic error message."""
        resp = self.client.post(
            "/api/auth/login",
            data=json.dumps({"username": "admin_alice", "password": "WrongPassword!"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "Invalid credentials")

    # -------------------------------------------------------------------------
    # 2. Authentication Status Endpoint
    # -------------------------------------------------------------------------
    def test_auth_status_endpoint(self):
        """Verify /api/auth/status reflects active session state accurately."""
        # Unauthenticated
        resp = self.client.get("/api/auth/status")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["authenticated"])

        # Authenticate
        self._login("admin_alice", "AdminPass123!")

        resp = self.client.get("/api/auth/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["user"]["username"], "admin_alice")
        self.assertEqual(data["user"]["role"], "admin")
        self.assertIsNotNone(data["csrf_token"])

    # -------------------------------------------------------------------------
    # 3. Protected Administrator Test Endpoint & Role Separation
    # -------------------------------------------------------------------------
    def test_role_separation_on_admin_endpoint(self):
        """Verify only users with role='admin' can access /api/admin/test."""
        # 1. Unauthenticated client receives 401
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 401)

        # 2. Operator client receives 403 Forbidden
        self.client.delete_cookie("session_token")
        self._login("operator_bob", "OperatorPass123!")
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Insufficient privileges", resp.get_json()["error"])

        # 3. Auditor client receives 403 Forbidden
        self.client.delete_cookie("session_token")
        self._login("auditor_charlie", "AuditorPass123!")
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Insufficient privileges", resp.get_json()["error"])

        # 4. Administrator client succeeds (200 OK)
        self.client.delete_cookie("session_token")
        self._login("admin_alice", "AdminPass123!")
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"], "admin_alice")
        self.assertEqual(data["role"], "admin")

    # -------------------------------------------------------------------------
    # 4. CSRF Enforcement on Mutating Endpoints
    # -------------------------------------------------------------------------
    def test_csrf_protection_on_mutating_endpoints(self):
        """Verify state-changing POST /api/admin/echo requires valid X-CSRF-Token."""
        _, csrf_token = self._login("admin_alice", "AdminPass123!")

        # Case A: Missing CSRF token header -> 403 Forbidden
        resp = self.client.post(
            "/api/admin/echo",
            data=json.dumps({"payload": "test_data"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Missing X-CSRF-Token", resp.get_json()["error"])

        # Case B: Invalid / mismatched CSRF token -> 403 Forbidden
        resp = self.client.post(
            "/api/admin/echo",
            headers={"X-CSRF-Token": "invalid_forged_token"},
            data=json.dumps({"payload": "test_data"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Invalid or mismatched token", resp.get_json()["error"])

        # Case C: Valid CSRF token -> 200 OK
        resp = self.client.post(
            "/api/admin/echo",
            headers={"X-CSRF-Token": csrf_token},
            data=json.dumps({"payload": "test_data"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["echo"]["payload"], "test_data")

    # -------------------------------------------------------------------------
    # 5. Logout & Session Invalidation
    # -------------------------------------------------------------------------
    def test_logout_invalidates_session_and_clears_cookie(self):
        """Verify POST /api/auth/logout invalidates session and prevents subsequent access."""
        _, csrf_token = self._login("admin_alice", "AdminPass123!")

        # Successfully access admin route
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 200)

        # Logout with CSRF token
        resp = self.client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": csrf_token},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["success"])

        # Subsequent admin call is rejected with 401
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 401)

    # -------------------------------------------------------------------------
    # 6. Direct API Authentication Bypass Attempts
    # -------------------------------------------------------------------------
    def test_direct_api_bypass_attempts(self):
        """Verify malicious or forged headers cannot bypass authentication."""
        # Forged Authorization header
        resp = self.client.get("/api/admin/test", headers={"Authorization": "Bearer fake_token_abc123"})
        self.assertEqual(resp.status_code, 401)

        # Forged cookie
        self.client.set_cookie(key="session_token", value="tampered_session_token")
        resp = self.client.get("/api/admin/test")
        self.assertEqual(resp.status_code, 401)

    # -------------------------------------------------------------------------
    # 7. Existing Assessment API Preservation & Remote Access Control
    # -------------------------------------------------------------------------
    def test_existing_assessment_api_remains_operational(self):
        """Verify existing assessment endpoints remain fully operational on localhost."""
        # 1. System status endpoint
        resp = self.client.get("/api/system/status")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "online")

        # 2. System resources endpoint
        resp = self.client.get("/api/system/resources")
        self.assertEqual(resp.status_code, 200)

        # 3. Assessment listing endpoint
        resp = self.client.get("/api/assessments")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("sessions", resp.get_json())

        # 4. Start assessment endpoint (parameter validation preserved)
        resp = self.client.post(
            "/api/assessments/start",
            data=json.dumps({"target_url": ""}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Target URL is required", resp.get_json()["error"])

    def test_remote_client_access_control(self):
        """Verify unauthenticated remote clients cannot start, cancel, or inspect assessments."""
        remote_env = {"REMOTE_ADDR": "192.168.1.150"}

        # Unauthenticated remote start is rejected (401)
        resp = self.client.post(
            "/api/assessments/start",
            environ_base=remote_env,
            data=json.dumps({"target_url": "http://127.0.0.1:5050"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Authentication required", resp.get_json()["error"])

        # Unauthenticated remote findings inspection is rejected (401)
        resp = self.client.get("/api/assessments/fake_id/findings", environ_base=remote_env)
        self.assertEqual(resp.status_code, 401)

        # Authenticated Auditor on remote IP: Read allowed, Write blocked (403)
        self._login("auditor_charlie", "AuditorPass123!")
        resp = self.client.get("/api/assessments/fake_id/findings", environ_base=remote_env)
        self.assertEqual(resp.status_code, 200)

        resp = self.client.post(
            "/api/assessments/start",
            environ_base=remote_env,
            data=json.dumps({"target_url": "http://127.0.0.1:5050"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Auditor role is strictly read-only", resp.get_json()["error"])

    # -------------------------------------------------------------------------
    # 8. Database Non-Destructive Extension & Preservation
    # -------------------------------------------------------------------------
    def test_database_tables_and_preservation(self):
        """Verify both existing assessment tables and new authentication tables coexist intact."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cursor.fetchall()}

            # Existing assessment tables
            expected_existing = {
                "sessions",
                "plans",
                "traffic_log",
                "findings",
                "tool_executions",
                "specifications",
                "zap_scans",
            }
            # New authentication tables
            expected_new = {
                "users",
                "admin_sessions",
                "admin_audit_log",
            }

            self.assertTrue(expected_existing.issubset(tables), f"Missing existing tables: {expected_existing - tables}")
            self.assertTrue(expected_new.issubset(tables), f"Missing new tables: {expected_new - tables}")

    # -------------------------------------------------------------------------
    # 9. First-Run Setup API & Forced Password Change Enforcement
    # -------------------------------------------------------------------------
    def test_first_run_setup_api_and_recreation_prevention(self):
        """Verify /api/auth/setup endpoint behaviors across system lifecycle."""
        # Fresh store without any users
        fresh_store = EvidenceStore(db_path=":memory:")
        fresh_sess_svc = SessionService(fresh_store)
        fresh_auth_svc = AuthenticationService(store=fresh_store, session_service=fresh_sess_svc, iterations=5_000)
        fresh_app = create_dashboard_app(
            session_manager=DashboardSessionManager(db_path=":memory:", store=fresh_store),
            auth_service=fresh_auth_svc,
            session_service=fresh_sess_svc,
        )
        client = fresh_app.test_client()

        # Status indicates setup_required
        res = client.get("/api/auth/status")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["setup_required"])

        # Setup initial administrator
        setup_res = client.post(
            "/api/auth/setup",
            data=json.dumps({"username": "first_admin", "password": "InitialAdminPass123!"}),
            content_type="application/json",
        )
        self.assertEqual(setup_res.status_code, 201)
        self.assertTrue(setup_res.get_json()["success"])

        # Subsequent setup attempt returns 400
        dup_res = client.post(
            "/api/auth/setup",
            data=json.dumps({"username": "second_admin", "password": "InitialAdminPass123!"}),
            content_type="application/json",
        )
        self.assertEqual(dup_res.status_code, 400)

        # Deleting admin user should still block silent re-setup with 403
        with fresh_store._get_connection() as conn:
            conn.cursor().execute("DELETE FROM users WHERE username = 'first_admin'")
            conn.commit()

        blocked_res = client.post(
            "/api/auth/setup",
            data=json.dumps({"username": "recreated_admin", "password": "InitialAdminPass123!"}),
            content_type="application/json",
        )
        self.assertEqual(blocked_res.status_code, 403)
        self.assertIn("silent administrator recreation is forbidden", blocked_res.get_json()["error"].lower())

    def test_must_change_password_blocks_admin_routes_until_changed(self):
        """Verify accounts flagged must_change_password cannot access admin routes until password changed."""
        user = self.auth_service.create_user(
            username="temp_op",
            password="TemporaryPass123!",
            role=Role.ADMIN.value,
        )
        with self.store._get_connection() as conn:
            conn.cursor().execute("UPDATE users SET must_change_password = 1 WHERE id = ?", (user["id"],))
            conn.commit()

        login_res = self.client.post(
            "/api/auth/login",
            data=json.dumps({"username": "temp_op", "password": "TemporaryPass123!"}),
            content_type="application/json",
        )
        self.assertEqual(login_res.status_code, 200)
        login_json = login_res.json
        csrf_token = login_json["csrf_token"]
        self.assertTrue(login_json["must_change_password"])

        # Attempt to access protected admin route -> blocked 403
        admin_res = self.client.get("/api/admin/test")
        self.assertEqual(admin_res.status_code, 403)
        self.assertTrue(admin_res.get_json().get("must_change_password"))

        # Calling change-password endpoint succeeds
        change_res = self.client.post(
            "/api/auth/change-password",
            data=json.dumps({
                "current_password": "TemporaryPass123!",
                "new_password": "NewPermanentPass123!",
            }),
            content_type="application/json",
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(change_res.status_code, 200)
        self.assertTrue(change_res.get_json()["success"])

        # Now protected admin route succeeds with 200
        admin_res2 = self.client.get("/api/admin/test")
        self.assertEqual(admin_res2.status_code, 200)
        self.assertTrue(admin_res2.get_json()["success"])


if __name__ == "__main__":
    unittest.main()
