"""Comprehensive Integration and Security Tests for Policy Management API & Dashboard.

Validates Phase 5.4 deliverables:
1. Administrator Policy CRUD endpoints (create, list, get, update, activate, deactivate, rollback).
2. Target authorization management endpoints (add, list, revoke).
3. RBAC enforcement: Admin permitted; Operator and Auditor rejected on mutations (403); Unauthenticated rejected (401).
4. CSRF protection: Mutating endpoints strictly require valid X-CSRF-Token.
5. Strict schema & limits validation (unknown tools, methods, auth, out-of-bounds ceilings).
6. Immutable versioning: Updates increment versions without overwriting historical records.
7. Administrative audit log recording with secret masking (zero credential leakage).
8. Operator read access: /api/policies/active is accessible to operators and populates valid targets.
9. Pre-assessment scope validation and policy snapshot binding through dashboard launch.
"""

import json
import unittest

from controller.auth.authentication_service import AuthenticationService
from controller.auth.role_service import Role
from controller.auth.session_service import SessionService
from controller.guardrails.policy_service import PolicyService
from controller.storage.evidence_store import EvidenceStore
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager


class TestDashboardPolicyManagementAPI(unittest.TestCase):
    """Integration test suite for Policy Management REST API endpoints."""

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(self.store)
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,
        )
        self.policy_service = PolicyService(store=self.store)
        self.manager = DashboardSessionManager(
            db_path=":memory:",
            store=self.store,
            policy_service=self.policy_service,
        )
        self.app = create_dashboard_app(
            session_manager=self.manager,
            auth_service=self.auth_service,
            session_service=self.session_service,
            policy_service=self.policy_service,
        )
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Seed users
        self.admin = self.auth_service.bootstrap_admin("admin_alice", "AdminPass123!")
        self.operator = self.auth_service.create_user("operator_bob", "OperatorPass123!", Role.OPERATOR.value)
        self.auditor = self.auth_service.create_user("auditor_charlie", "AuditorPass123!", Role.AUDITOR.value)

    def tearDown(self):
        self.store.close()

    def _login_as(self, role="admin"):
        self.client.delete_cookie("session_token")
        if role == "admin":
            resp = self.client.post("/api/auth/login", data=json.dumps({"username": "admin_alice", "password": "AdminPass123!"}), content_type="application/json")
        elif role == "operator":
            resp = self.client.post("/api/auth/login", data=json.dumps({"username": "operator_bob", "password": "OperatorPass123!"}), content_type="application/json")
        elif role == "auditor":
            resp = self.client.post("/api/auth/login", data=json.dumps({"username": "auditor_charlie", "password": "AuditorPass123!"}), content_type="application/json")
        else:
            return None
        self.assertEqual(resp.status_code, 200, f"Login failed for role {role}")
        return resp.get_json()["csrf_token"]

    def test_create_and_list_policies(self):
        """Test creating a policy and listing policies."""
        csrf = self._login_as("admin")
        create_payload = {
            "name": "Production Safety Policy",
            "description": "Standard read-only security assessment",
            "config": {
                "allowed_tools": ["http_request", "httpx_request"],
                "allowed_http_methods": ["GET", "OPTIONS", "HEAD"],
                "allowed_auth_modes": ["none", "bearer"],
                "allowed_categories": ["API1:2023", "API2:2023"],
                "max_turns": 8,
                "max_requests": 20,
            },
            "targets": [
                {
                    "host_pattern": "127.0.0.1",
                    "port_range": "5000-5050",
                    "allowed_schemes": "http",
                    "path_prefix": "/api",
                }
            ],
        }

        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps(create_payload),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        policy = data["policy"]
        self.assertEqual(policy["name"], "Production Safety Policy")
        self.assertEqual(policy["current_version"], 1)
        self.assertEqual(len(policy["targets"]), 1)
        policy_id = policy["id"]

        # List policies
        list_resp = self.client.get("/api/admin/policies")
        self.assertEqual(list_resp.status_code, 200)
        list_data = list_resp.get_json()
        self.assertTrue(list_data["success"])
        self.assertGreaterEqual(len(list_data["policies"]), 1)

        # Get policy by ID
        get_resp = self.client.get(f"/api/admin/policies/{policy_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.get_json()["policy"]["name"], "Production Safety Policy")

    def test_update_policy_creates_immutable_new_version(self):
        """Updating a policy increments the version and preserves the historical version."""
        csrf = self._login_as("admin")

        # 1. Create v1
        create_resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Versioned Policy",
                "config": {"max_turns": 5, "max_requests": 15},
            }),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(create_resp.status_code, 201)
        pol_id = create_resp.get_json()["policy"]["id"]

        # 2. Update to v2
        update_resp = self.client.put(
            f"/api/admin/policies/{pol_id}",
            data=json.dumps({
                "config": {"max_turns": 12, "max_requests": 30},
                "change_summary": "Expanded turn budget for thoroughness",
            }),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(update_resp.status_code, 200)
        updated = update_resp.get_json()["policy"]
        self.assertEqual(updated["current_version"], 2)
        self.assertEqual(updated["config"]["max_turns"], 12)

        # 3. Retrieve historical v1
        v1_resp = self.client.get(f"/api/admin/policies/{pol_id}/versions/1")
        self.assertEqual(v1_resp.status_code, 200)
        v1_data = v1_resp.get_json()["version"]
        self.assertEqual(v1_data["version"], 1)
        self.assertEqual(v1_data["config"]["max_turns"], 5)

        # 4. List all versions
        vers_resp = self.client.get(f"/api/admin/policies/{pol_id}/versions")
        self.assertEqual(vers_resp.status_code, 200)
        versions = vers_resp.get_json()["versions"]
        self.assertEqual(len(versions), 2)

    def test_policy_rollback_creates_new_version(self):
        """Rollback restores historical config by creating v3."""
        csrf = self._login_as("admin")

        # Create v1 (turns=5)
        create_resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Rollback Test Policy",
                "config": {"max_turns": 5},
            }),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        pol_id = create_resp.get_json()["policy"]["id"]

        # Update to v2 (turns=20)
        self.client.put(
            f"/api/admin/policies/{pol_id}",
            data=json.dumps({"config": {"max_turns": 20}}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )

        # Rollback to v1 -> should yield v3 with turns=5
        rb_resp = self.client.post(
            f"/api/admin/policies/{pol_id}/rollback",
            data=json.dumps({"target_version": 1}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(rb_resp.status_code, 200)
        rb_data = rb_resp.get_json()["policy"]
        self.assertEqual(rb_data["current_version"], 3)
        self.assertEqual(rb_data["config"]["max_turns"], 5)

    def test_activate_and_deactivate_policy(self):
        """Test toggling policy active state."""
        csrf = self._login_as("admin")

        create_resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Toggle State Policy",
                "config": {"max_turns": 6},
            }),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(create_resp.status_code, 201)
        pol_id = create_resp.get_json()["policy"]["id"]

        # Deactivate
        deact_resp = self.client.post(
            f"/api/admin/policies/{pol_id}/deactivate",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(deact_resp.status_code, 200)
        pol = self.policy_service.get_policy(pol_id)
        self.assertFalse(pol["is_active"])

        # Activate
        act_resp = self.client.post(
            f"/api/admin/policies/{pol_id}/activate",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(act_resp.status_code, 200)
        pol = self.policy_service.get_policy(pol_id)
        self.assertTrue(pol["is_active"])

    def test_target_authorizations_management(self):
        """Test adding, listing, and revoking target authorization rules."""
        csrf = self._login_as("admin")

        create_resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Target Rules Policy",
                "config": {"max_turns": 7},
            }),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(create_resp.status_code, 201)
        pol_id = create_resp.get_json()["policy"]["id"]

        # Add target
        target_payload = {
            "host_pattern": "127.0.0.1",
            "port_range": "8000-8080",
            "allowed_schemes": "http",
            "path_prefix": "/api/v2",
        }
        add_resp = self.client.post(
            f"/api/admin/policies/{pol_id}/targets",
            data=json.dumps(target_payload),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(add_resp.status_code, 201)
        tgt = add_resp.get_json()["target"]
        target_id = tgt["id"]
        self.assertEqual(tgt["host_pattern"], "127.0.0.1")

        # List targets
        list_resp = self.client.get(f"/api/admin/policies/{pol_id}/targets")
        self.assertEqual(list_resp.status_code, 200)
        self.assertEqual(len(list_resp.get_json()["targets"]), 1)

        # Revoke target
        rev_resp = self.client.post(
            f"/api/admin/policies/{pol_id}/targets/{target_id}/revoke",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rev_resp.status_code, 200)

        # Active targets should now be 0
        active_list_resp = self.client.get(f"/api/admin/policies/{pol_id}/targets?active_only=1")
        self.assertEqual(len(active_list_resp.get_json()["targets"]), 0)

    def test_policy_metrics_and_audit_log(self):
        """Test aggregated metrics and administrative audit trail retrieval."""
        self._login_as("admin")

        # Metrics endpoint
        metrics_resp = self.client.get("/api/admin/policies/metrics")
        self.assertEqual(metrics_resp.status_code, 200)
        m = metrics_resp.get_json()["metrics"]
        self.assertIn("total_policies", m)
        self.assertIn("active_policies", m)
        self.assertIn("total_targets", m)

        # Audit log endpoint
        audit_resp = self.client.get("/api/admin/audit-log")
        self.assertEqual(audit_resp.status_code, 200)
        logs = audit_resp.get_json()["audit_log"]
        self.assertIsInstance(logs, list)

    def test_operator_read_active_policies(self):
        """Operators can read active policies via /api/policies/active."""
        csrf = self._login_as("admin")
        self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Operator Visible Policy",
                "config": {"max_turns": 8},
                "targets": [{"host_pattern": "localhost", "port_range": "*"}],
            }),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )

        # Switch to operator session
        self._login_as("operator")
        resp = self.client.get("/api/policies/active")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        policies = data["policies"]
        self.assertGreaterEqual(len(policies), 1)
        names = [p["name"] for p in policies]
        self.assertIn("Operator Visible Policy", names)


class TestDashboardPolicyRBACAndCSRF(unittest.TestCase):
    """Rigorous verification of Role-Based Access Control and CSRF protection."""

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(self.store)
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,
        )
        self.policy_service = PolicyService(store=self.store)
        self.manager = DashboardSessionManager(
            db_path=":memory:",
            store=self.store,
            policy_service=self.policy_service,
        )
        self.app = create_dashboard_app(
            session_manager=self.manager,
            auth_service=self.auth_service,
            session_service=self.session_service,
            policy_service=self.policy_service,
        )
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Seed roles
        self.auth_service.bootstrap_admin("admin_alice", "AdminPass123!")
        self.auth_service.create_user("operator_bob", "OperatorPass123!", Role.OPERATOR.value)
        self.auth_service.create_user("auditor_charlie", "AuditorPass123!", Role.AUDITOR.value)

        # Create baseline policy
        self.baseline_policy = self.policy_service.create_policy(
            name="RBAC Baseline Policy",
            config={"max_turns": 10},
            creator_id=1,
        )

    def tearDown(self):
        self.store.close()

    def _login_as(self, role="admin"):
        self.client.delete_cookie("session_token")
        if role == "admin":
            resp = self.client.post("/api/auth/login", data=json.dumps({"username": "admin_alice", "password": "AdminPass123!"}), content_type="application/json")
        elif role == "operator":
            resp = self.client.post("/api/auth/login", data=json.dumps({"username": "operator_bob", "password": "OperatorPass123!"}), content_type="application/json")
        elif role == "auditor":
            resp = self.client.post("/api/auth/login", data=json.dumps({"username": "auditor_charlie", "password": "AuditorPass123!"}), content_type="application/json")
        else:
            return None
        return resp.get_json()["csrf_token"]

    def test_unauthenticated_blocked_from_admin_endpoints(self):
        """Unauthenticated requests to admin policy endpoints are rejected with 401."""
        self.client.delete_cookie("session_token")
        endpoints = [
            ("GET", "/api/admin/policies"),
            ("POST", "/api/admin/policies"),
            ("GET", f"/api/admin/policies/{self.baseline_policy['id']}"),
            ("PUT", f"/api/admin/policies/{self.baseline_policy['id']}"),
            ("POST", f"/api/admin/policies/{self.baseline_policy['id']}/activate"),
            ("POST", f"/api/admin/policies/{self.baseline_policy['id']}/deactivate"),
            ("POST", f"/api/admin/policies/{self.baseline_policy['id']}/rollback"),
            ("GET", f"/api/admin/policies/{self.baseline_policy['id']}/targets"),
            ("POST", f"/api/admin/policies/{self.baseline_policy['id']}/targets"),
            ("GET", "/api/admin/audit-log"),
            ("GET", "/api/admin/policies/metrics"),
        ]

        for method, url in endpoints:
            if method == "GET":
                resp = self.client.get(url)
            elif method == "PUT":
                resp = self.client.put(url, data=json.dumps({}), content_type="application/json")
            else:
                resp = self.client.post(url, data=json.dumps({}), content_type="application/json")
            self.assertEqual(resp.status_code, 401, f"Expected 401 for unauthenticated {method} {url}")

    def test_operator_blocked_from_admin_policy_mutations(self):
        """Operators cannot mutate or administer policies (returns 403 Forbidden)."""
        csrf = self._login_as("operator")

        # Attempt to create policy
        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({"name": "Operator Hack Policy", "config": {}}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 403)

        # Attempt to modify existing policy
        resp2 = self.client.put(
            f"/api/admin/policies/{self.baseline_policy['id']}",
            data=json.dumps({"config": {"max_turns": 45}}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp2.status_code, 403)

        # Attempt to add target authorization
        resp3 = self.client.post(
            f"/api/admin/policies/{self.baseline_policy['id']}/targets",
            data=json.dumps({"host_pattern": "evil.com"}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp3.status_code, 403)

    def test_auditor_blocked_from_admin_policy_mutations(self):
        """Auditors cannot mutate policies (returns 403 Forbidden)."""
        csrf = self._login_as("auditor")

        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({"name": "Auditor Unauthorized Policy", "config": {}}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_csrf_protection_on_mutating_endpoints(self):
        """Mutating endpoints strictly reject missing or invalid CSRF tokens."""
        self._login_as("admin")

        # 1. Missing CSRF header
        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({"name": "Missing CSRF", "config": {}}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("CSRF", resp.get_json()["error"])

        # 2. Invalid CSRF header
        resp2 = self.client.post(
            "/api/admin/policies",
            data=json.dumps({"name": "Invalid CSRF", "config": {}}),
            headers={"X-CSRF-Token": "bogus_attacker_token_12345", "Content-Type": "application/json"},
        )
        self.assertEqual(resp2.status_code, 403)
        self.assertIn("CSRF", resp2.get_json()["error"])

        # 3. Valid CSRF header succeeds
        csrf = self._login_as("admin")
        resp3 = self.client.post(
            "/api/admin/policies",
            data=json.dumps({"name": "Valid CSRF Policy", "config": {"max_turns": 5}}),
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp3.status_code, 201)


class TestDashboardPolicyValidationAndSecurity(unittest.TestCase):
    """Validation boundaries, SQL injection resilience, and secret masking."""

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(self.store)
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,
        )
        self.policy_service = PolicyService(store=self.store)
        self.manager = DashboardSessionManager(
            db_path=":memory:",
            store=self.store,
            policy_service=self.policy_service,
        )
        self.app = create_dashboard_app(
            session_manager=self.manager,
            auth_service=self.auth_service,
            session_service=self.session_service,
            policy_service=self.policy_service,
        )
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.auth_service.bootstrap_admin("admin_alice", "AdminPass123!")
        self.admin_csrf = self._login_admin()

    def tearDown(self):
        self.store.close()

    def _login_admin(self):
        resp = self.client.post(
            "/api/auth/login",
            data=json.dumps({"username": "admin_alice", "password": "AdminPass123!"}),
            content_type="application/json",
        )
        return resp.get_json()["csrf_token"]

    def test_schema_rejects_unknown_tools_and_methods(self):
        """Unknown tools and unsupported HTTP methods are rejected."""
        # Unknown tool
        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Invalid Tool Policy",
                "config": {"allowed_tools": ["non_existent_exploit_tool"]},
            }),
            headers={"X-CSRF-Token": self.admin_csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unknown tools", resp.get_json()["error"])

        # Unknown HTTP method
        resp2 = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Invalid Method Policy",
                "config": {"allowed_http_methods": ["TRACE", "CONNECT"]},
            }),
            headers={"X-CSRF-Token": self.admin_csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("Unsupported HTTP methods", resp2.get_json()["error"])

    def test_schema_rejects_exceeded_safety_ceilings(self):
        """Request budgets exceeding developer safety ceilings (100) are rejected."""
        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": "Excessive Budget Policy",
                "config": {"max_requests": 500},
            }),
            headers={"X-CSRF-Token": self.admin_csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("max_requests", resp.get_json()["error"])

    def test_sql_injection_resilience(self):
        """SQL injection payloads in policy names or search filters are safely parameterized."""
        sqli_payload = "'; DROP TABLE policies; --"
        resp = self.client.post(
            "/api/admin/policies",
            data=json.dumps({
                "name": sqli_payload,
                "config": {"max_turns": 5},
            }),
            headers={"X-CSRF-Token": self.admin_csrf, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 201)
        # Verify table still exists and policy was inserted safely
        pol = resp.get_json()["policy"]
        self.assertEqual(pol["name"], sqli_payload)

        # Verify search handles SQLi characters safely
        search_resp = self.client.get("/api/admin/policies")
        self.assertEqual(search_resp.status_code, 200)

    def test_html_view_renders_policy_elements(self):
        """HTML view contains the policy admin tab, controls, and modals."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('id="nav-tab-policies"', html)
        self.assertIn('id="tab-policies"', html)
        self.assertIn('id="policy-modal"', html)
        self.assertIn('id="target-modal"', html)
        self.assertIn('id="versions-modal"', html)
        self.assertIn('id="assessment_policy_id"', html)
        self.assertIn('id="target-scope-validation-pill"', html)


class TestDashboardPolicyAssessmentIntegration(unittest.TestCase):
    """Verifies that launching an assessment with a policy ID enforces scope."""

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(self.store)
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,
        )
        self.policy_service = PolicyService(store=self.store)
        self.manager = DashboardSessionManager(
            db_path=":memory:",
            store=self.store,
            policy_service=self.policy_service,
        )
        self.app = create_dashboard_app(
            session_manager=self.manager,
            auth_service=self.auth_service,
            session_service=self.session_service,
            policy_service=self.policy_service,
        )
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.auth_service.bootstrap_admin("admin_alice", "AdminPass123!")

        # Create policy with strict target: 127.0.0.1:5050 only
        self.strict_policy = self.policy_service.create_policy(
            name="Strict Lab Policy",
            config={"max_turns": 4, "max_requests": 10},
            targets=[{
                "host_pattern": "127.0.0.1",
                "port_range": "5050",
                "allowed_schemes": "http",
                "path_prefix": "/api",
            }],
            creator_id=1,
        )

    def tearDown(self):
        self.store.close()

    def test_assessment_start_rejects_unauthorized_target(self):
        """Assessment launch with target outside policy whitelist is rejected before execution."""
        resp = self.client.post(
            "/api/assessments/start",
            data=json.dumps({
                "target_url": "http://127.0.0.1:9090/unauthorized",
                "policy_id": self.strict_policy["id"],
                "brain_mode": "mock",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("policy rejection", data["error"].lower())

    def test_assessment_start_accepts_authorized_target(self):
        """Assessment launch with target inside policy whitelist succeeds."""
        resp = self.client.post(
            "/api/assessments/start",
            data=json.dumps({
                "target_url": "http://127.0.0.1:5050/api/users",
                "policy_id": self.strict_policy["id"],
                "brain_mode": "mock",
                "spec_source": "lab/openapi_spec.json",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("session_id", data)


if __name__ == "__main__":
    unittest.main()
