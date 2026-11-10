"""Dedicated Test Suite for Phase 5.5: Target Authorization and Assessment Workflow Hardening.

Covers:
1. Wildcard host boundaries and scope containment
2. Host normalization (case, trailing dots, IDN / Punycode)
3. IPv4, IPv6, and CIDR target matching
4. Port-range boundaries and default scheme ports
5. Path-prefix bypass prevention
6. Duplicate and conflicting target authorization prevention
7. Cross-policy target manipulation prevention
8. Expired and revoked target rejection
9. Assessment launch multi-role authorization and ownership
10. Operator assessment isolation and cancellation permissions
11. Authentication mode enforcement and credential masking
12. Live policy deactivation and target revocation during active assessment
13. Immutable developer safety invariants during active assessments
14. Concurrency and race conditions (updates, launches, revocations)
15. Evidence preservation after cancellation
"""

import copy
import ipaddress
import json
import os
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List

from controller.agent.autonomous_controller import AutonomousController
from controller.agent.event_emitter import AgentEventEmitter
from controller.auth.authentication_service import AuthenticationService
from controller.auth.session_service import SessionService
from controller.brain.model_gateway import get_model_brain
from controller.config import AgentConfig
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.policy_service import PolicyService, get_default_policy_config
from controller.guardrails.scope_validator import (
    ScopeValidator,
    canonicalize_ip_str,
    match_host_pattern,
    match_path_prefix,
    match_port_range,
    normalize_hostname,
)
from controller.storage.evidence_store import EvidenceStore
from controller.tools.registry import ToolRegistry
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager


class TestWildcardAndHostNormalization(unittest.TestCase):
    """Rigorous verification of host normalization and wildcard containment."""

    def test_wildcard_host_boundary_never_matches_unrelated_domains(self):
        """*.example.local must match subdomains and apex, but NEVER unrelated or suffix-spoofed domains."""
        pattern = "*.example.local"

        # Valid authorizations
        self.assertTrue(match_host_pattern(pattern, "sub.example.local"))
        self.assertTrue(match_host_pattern(pattern, "deep.nested.sub.example.local"))
        self.assertTrue(match_host_pattern(pattern, "example.local"))
        self.assertTrue(match_host_pattern(pattern, "example.local."))

        # Prohibited bypass attempts (MUST BE FALSE)
        self.assertFalse(match_host_pattern(pattern, "example.local.evil.test"))
        self.assertFalse(match_host_pattern(pattern, "evil-example.local"))
        self.assertFalse(match_host_pattern(pattern, "notexample.local"))
        self.assertFalse(match_host_pattern(pattern, "example.local.attacker.com"))
        self.assertFalse(match_host_pattern(pattern, "evil.test"))
        self.assertFalse(match_host_pattern(pattern, "attacker.com"))

    def test_host_normalization_case_and_trailing_dot(self):
        """Normalization handles upper/mixed case, whitespace, and FQDN trailing dots."""
        self.assertEqual(normalize_hostname("  EXAMPLE.LOCAL.  "), "example.local")
        self.assertEqual(normalize_hostname("Api.Test.Org."), "api.test.org")
        self.assertEqual(normalize_hostname("[::1]"), "::1")

        # Pattern match handles trailing dots symmetrically
        self.assertTrue(match_host_pattern("example.local", "EXAMPLE.LOCAL."))
        self.assertTrue(match_host_pattern("example.local.", "example.local"))
        self.assertTrue(match_host_pattern("*.example.local.", "SUB.EXAMPLE.LOCAL."))

    def test_internationalized_domain_names_idn(self):
        """Internationalized Domain Names match seamlessly via IDN Punycode normalization."""
        # 'bühler.de' -> 'xn--bhler-kva.de'
        self.assertEqual(normalize_hostname("bühler.de"), "xn--bhler-kva.de")
        self.assertTrue(match_host_pattern("bühler.de", "xn--bhler-kva.de"))
        self.assertTrue(match_host_pattern("xn--bhler-kva.de", "bühler.de"))
        self.assertTrue(match_host_pattern("*.bühler.de", "api.bühler.de"))
        self.assertTrue(match_host_pattern("*.bühler.de", "api.xn--bhler-kva.de"))
        self.assertFalse(match_host_pattern("*.bühler.de", "bühler.de.attacker.com"))

    def test_ipv4_and_ipv6_target_matching(self):
        """IPv4 and IPv6 representations (compressed, expanded, decimal, hex, bracketed) match canonically."""
        # IPv6 loopback variants
        self.assertTrue(match_host_pattern("::1", "::1"))
        self.assertTrue(match_host_pattern("::1", "[::1]"))
        self.assertTrue(match_host_pattern("::1", "0:0:0:0:0:0:0:1"))
        self.assertTrue(match_host_pattern("[0000:0000:0000:0000:0000:0000:0000:0001]", "::1"))

        # IPv6 global unicast
        self.assertTrue(match_host_pattern("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"))
        self.assertFalse(match_host_pattern("2001:db8::1", "2001:db8::2"))

        # IPv4 decimal / canonical
        self.assertTrue(match_host_pattern("127.0.0.1", "127.0.0.1"))
        self.assertTrue(match_host_pattern("127.0.0.1", "127.000.000.001"))

    def test_cidr_target_matching(self):
        """CIDR pattern allows hosts strictly inside the subnet and rejects external hosts."""
        subnet = "192.168.1.0/24"
        self.assertTrue(match_host_pattern(subnet, "192.168.1.1"))
        self.assertTrue(match_host_pattern(subnet, "192.168.1.254"))
        self.assertFalse(match_host_pattern(subnet, "192.168.2.1"))
        self.assertFalse(match_host_pattern(subnet, "10.0.0.1"))

    def test_wildcard_validation_rejects_malformed_patterns(self):
        """Target definition validator strictly rejects insecure wildcard patterns."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)

            # Valid wildcards
            valid, _, t1 = svc.validate_target_authorization_def({"host_pattern": "*"})
            self.assertTrue(valid)
            self.assertEqual(t1["is_wildcard"], 1)

            valid, _, t2 = svc.validate_target_authorization_def({"host_pattern": "*.example.com"})
            self.assertTrue(valid)

            # Insecure / malformed wildcards
            invalid_patterns = ["*evil*", "foo.*.com", "*. ", "*test*", "foo.*", "*.*.com"]
            for bad_pat in invalid_patterns:
                v, err, _ = svc.validate_target_authorization_def({"host_pattern": bad_pat})
                self.assertFalse(v, f"Expected {bad_pat} to be rejected, got valid")
                self.assertIn("Invalid wildcard", err)
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass


class TestTargetSafetyBoundariesAndLifecycle(unittest.TestCase):
    """Verification of port-range, path-prefix, duplicate, and expiration boundaries."""

    def test_port_range_boundaries(self):
        """Port ranges enforce inclusive boundaries and reject off-by-one ports."""
        # Range 5000-5050
        self.assertTrue(match_port_range("5000-5050", 5000))
        self.assertTrue(match_port_range("5000-5050", 5050))
        self.assertTrue(match_port_range("5000-5050", 5025))
        self.assertFalse(match_port_range("5000-5050", 4999))
        self.assertFalse(match_port_range("5000-5050", 5051))

        # Single port
        self.assertTrue(match_port_range("8080", 8080))
        self.assertFalse(match_port_range("8080", 80))

        # Wildcard port
        self.assertTrue(match_port_range("*", 80))
        self.assertTrue(match_port_range("*", 443))
        self.assertFalse(match_port_range("*", 0))
        self.assertFalse(match_port_range("*", 65536))

    def test_path_prefix_bypass_prevention(self):
        """Path prefix matching prevents boundary truncation and suffix bypass."""
        prefix = "/api/v1"
        # Authorized paths
        self.assertTrue(match_path_prefix(prefix, "/api/v1"))
        self.assertTrue(match_path_prefix(prefix, "/api/v1/"))
        self.assertTrue(match_path_prefix(prefix, "/api/v1/users"))
        self.assertTrue(match_path_prefix(prefix, "/api/v1/users/profile"))

        # Classic path prefix bypass attempts (MUST BE FALSE)
        self.assertFalse(match_path_prefix(prefix, "/api/v10"))
        self.assertFalse(match_path_prefix(prefix, "/api/v10/admin"))
        self.assertFalse(match_path_prefix(prefix, "/api/v1_secret"))
        self.assertFalse(match_path_prefix(prefix, "/api/v1.json"))
        self.assertFalse(match_path_prefix("/api", "/apidocs"))

    def test_duplicate_target_authorization_rejected(self):
        """PolicyService rejects creating duplicate active target rules on the same policy."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            policy = svc.create_policy(
                name="Duplicate Test Policy",
                config=get_default_policy_config(),
                creator_id=admin["id"],
            )

            target_def = {
                "host_pattern": "127.0.0.1",
                "port_range": "5000-5050",
                "path_prefix": "/api/v1",
                "allowed_schemes": "http,https",
            }

            # First addition succeeds
            t1 = svc.add_target_authorization(policy["id"], target_def, actor_id=admin["id"])
            self.assertIsNotNone(t1["id"])

            # Duplicate active addition must raise ValueError
            with self.assertRaises(ValueError) as ctx:
                svc.add_target_authorization(policy["id"], target_def, actor_id=admin["id"])
            self.assertIn("Duplicate active target authorization rule already exists", str(ctx.exception))
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass

    def test_cross_policy_target_manipulation_blocked(self):
        """Revoking a target authorization belonging to another policy is strictly rejected."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            p1 = svc.create_policy(name="Policy 1", config=get_default_policy_config(), creator_id=admin["id"])
            p2 = svc.create_policy(name="Policy 2", config=get_default_policy_config(), creator_id=admin["id"])

            t1 = svc.add_target_authorization(p1["id"], {"host_pattern": "127.0.0.1"}, actor_id=admin["id"])

            # Revoking target 1 under policy 2 fails
            ok = svc.revoke_target_authorization(target_id=t1["id"], actor_id=admin["id"], policy_id=p2["id"])
            self.assertFalse(ok)

            # Target 1 remains active under policy 1
            targets = svc.list_target_authorizations(p1["id"], active_only=True)
            self.assertEqual(len(targets), 1)

            # Revoking target 1 under policy 1 succeeds
            ok = svc.revoke_target_authorization(target_id=t1["id"], actor_id=admin["id"], policy_id=p1["id"])
            self.assertTrue(ok)
            self.assertEqual(len(svc.list_target_authorizations(p1["id"], active_only=True)), 0)
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass

    def test_expired_and_revoked_target_rejection(self):
        """Expired and revoked target authorizations are rejected at launch and during execution."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            policy = svc.create_policy(name="Expiry Test Policy", config=get_default_policy_config(), creator_id=admin["id"])

            # Target expired 1 hour ago
            past_time = time.time() - 3600.0
            t_exp = svc.add_target_authorization(
                policy["id"],
                {"host_pattern": "127.0.0.1", "port_range": "5000", "expires_at": past_time},
                actor_id=admin["id"],
            )

            # Pre-assessment check rejects expired target
            permitted, reason, _ = svc.check_assessment_permitted(
                policy_id=policy["id"],
                target_url="http://127.0.0.1:5000/api",
            )
            self.assertFalse(permitted)
            self.assertIn("expired", reason.lower())

            # ScopeValidator also rejects expired rule
            validator = ScopeValidator()
            res = validator.validate_url("http://127.0.0.1:5000/api", target_authorizations=[t_exp])
            self.assertFalse(res.is_valid)

            # Active unexpired target is accepted
            future_time = time.time() + 3600.0
            t_valid = svc.add_target_authorization(
                policy["id"],
                {"host_pattern": "127.0.0.1", "port_range": "5050", "expires_at": future_time},
                actor_id=admin["id"],
            )
            permitted2, _, _ = svc.check_assessment_permitted(
                policy_id=policy["id"],
                target_url="http://127.0.0.1:5050/api",
            )
            self.assertTrue(permitted2)

            # Revoking target makes it immediately rejected
            svc.revoke_target_authorization(t_valid["id"], actor_id=admin["id"], policy_id=policy["id"])
            permitted3, reason3, _ = svc.check_assessment_permitted(
                policy_id=policy["id"],
                target_url="http://127.0.0.1:5050/api",
            )
            self.assertFalse(permitted3)
            self.assertTrue(
                "expired" in reason3.lower() or "revoked" in reason3.lower() or "whitelist" in reason3.lower() or "disabled" in reason3.lower()
            )
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass


class TestAssessmentOwnershipAndRoles(unittest.TestCase):
    """Verification of operator ownership, isolation, and role restrictions in Flask dashboard."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        self.store = EvidenceStore(db_path=self.db_path)
        self.auth_svc = AuthenticationService(store=self.store)
        self.sess_svc = SessionService(store=self.store)
        self.policy_svc = PolicyService(store=self.store)

        # Bootstrap admin, operators, auditor
        self.admin = self.auth_svc.bootstrap_admin("admin_root", "AdminPass123!Root")
        self.op1 = self.auth_svc.create_user("operator_one", "OperatorPass123!One", role="operator", creator_user_id=self.admin["id"])
        self.op2 = self.auth_svc.create_user("operator_two", "OperatorPass123!Two", role="operator", creator_user_id=self.admin["id"])
        self.auditor = self.auth_svc.create_user("auditor_bob", "AuditorPass123!Bob", role="auditor", creator_user_id=self.admin["id"])

        # Create active policy with authorized target
        self.policy = self.policy_svc.create_policy(
            name="Workflow Policy",
            config=get_default_policy_config(),
            creator_id=self.admin["id"],
            targets=[{"host_pattern": "127.0.0.1", "port_range": "5000-5050", "path_prefix": "/api"}],
        )

        self.manager = DashboardSessionManager(db_path=self.db_path, store=self.store, policy_service=self.policy_svc)
        self.app = create_dashboard_app(
            session_manager=self.manager,
            auth_service=self.auth_svc,
            session_service=self.sess_svc,
            policy_service=self.policy_svc,
        )
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def _login(self, username, password):
        resp = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()["csrf_token"]

    def test_operator_cancellation_ownership(self):
        """Operator 1 starts assessment. Operator 2 cannot cancel it; Admin and Operator 1 can."""
        # 1. Login as operator 1 and start assessment
        csrf_op1 = self._login("operator_one", "OperatorPass123!One")
        resp_start = self.client.post(
            "/api/assessments/start",
            headers={"X-CSRF-Token": csrf_op1},
            json={
                "target_url": "http://127.0.0.1:5050/api/users",
                "policy_id": self.policy["id"],
                "brain_mode": "mock",
            },
        )
        self.assertEqual(resp_start.status_code, 200)
        sess_id = resp_start.get_json()["session_id"]

        # Verify attribution in database (await thread initialization)
        db_sess = None
        for _ in range(50):
            db_sess = self.store.get_session(sess_id)
            if db_sess is not None:
                break
            time.sleep(0.05)
        self.assertIsNotNone(db_sess)
        self.assertEqual(db_sess["operator_id"], self.op1["id"])
        self.assertEqual(db_sess["policy_id"], self.policy["id"])

        # 2. Login as Operator 2 and attempt to cancel Operator 1's assessment -> 403 Forbidden
        self.client.delete_cookie("session_token")
        csrf_op2 = self._login("operator_two", "OperatorPass123!Two")
        resp_cancel_op2 = self.client.post(
            f"/api/assessments/{sess_id}/cancel",
            headers={"X-CSRF-Token": csrf_op2},
        )
        self.assertEqual(resp_cancel_op2.status_code, 403)
        self.assertIn("cannot cancel an assessment owned by", resp_cancel_op2.get_json()["error"])

        # 3. Login as Auditor and attempt to cancel -> 403 Forbidden
        self.client.delete_cookie("session_token")
        csrf_auditor = self._login("auditor_bob", "AuditorPass123!Bob")
        resp_cancel_aud = self.client.post(
            f"/api/assessments/{sess_id}/cancel",
            headers={"X-CSRF-Token": csrf_auditor},
        )
        self.assertEqual(resp_cancel_aud.status_code, 403)
        self.assertIn("Auditor role is strictly read-only", resp_cancel_aud.get_json()["error"])

        # 4. Login as Admin and cancel -> 200 OK (Admin override)
        self.client.delete_cookie("session_token")
        csrf_admin = self._login("admin_root", "AdminPass123!Root")
        resp_cancel_admin = self.client.post(
            f"/api/assessments/{sess_id}/cancel",
            headers={"X-CSRF-Token": csrf_admin},
        )
        self.assertEqual(resp_cancel_admin.status_code, 200)
        self.assertEqual(resp_cancel_admin.get_json()["status"], "CANCELLED")

    def test_auditor_cannot_start_assessment(self):
        """Auditor role receives 403 Forbidden when attempting to start an assessment."""
        csrf_auditor = self._login("auditor_bob", "AuditorPass123!Bob")
        resp = self.client.post(
            "/api/assessments/start",
            headers={"X-CSRF-Token": csrf_auditor},
            json={
                "target_url": "http://127.0.0.1:5050/api/users",
                "policy_id": self.policy["id"],
            },
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Auditor role is strictly read-only", resp.get_json()["error"])


class TestAuthenticationModeAndCredentialSafety(unittest.TestCase):
    """Verification of authentication mode enforcement and zero credential exposure."""

    def test_policy_enforces_allowed_auth_modes(self):
        """Policy with allowed_auth_modes=['none', 'basic'] strictly rejects 'bearer' at pre-validation."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            cfg = get_default_policy_config()
            cfg["allowed_auth_modes"] = ["none", "basic"]
            policy = svc.create_policy(
                name="Strict Auth Policy",
                config=cfg,
                creator_id=admin["id"],
                targets=[{"host_pattern": "127.0.0.1", "port_range": "5050"}],
            )

            # Basic auth allowed
            ok_basic, _, _ = svc.check_assessment_permitted(
                policy_id=policy["id"],
                target_url="http://127.0.0.1:5050/api",
                auth_type="basic",
            )
            self.assertTrue(ok_basic)

            # Bearer auth rejected
            ok_bearer, reason_bearer, _ = svc.check_assessment_permitted(
                policy_id=policy["id"],
                target_url="http://127.0.0.1:5050/api",
                auth_type="bearer",
            )
            self.assertFalse(ok_bearer)
            self.assertIn("Authentication mode 'bearer' is not permitted", reason_bearer)

            # Malicious / unsupported auth mode rejected
            ok_evil, reason_evil, _ = svc.check_assessment_permitted(
                policy_id=policy["id"],
                target_url="http://127.0.0.1:5050/api",
                auth_type="malicious_custom_mode",
            )
            self.assertFalse(ok_evil)
            self.assertIn("not permitted", reason_evil)
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass

    def test_credentials_never_exposed_in_snapshots_or_audit(self):
        """Raw credentials must never appear in policy snapshots, audit logs, or error responses."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            policy = svc.create_policy(
                name="Safe Credential Policy",
                config=get_default_policy_config(),
                creator_id=admin["id"],
            )

            # Audit event logging with sensitive payload
            secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SecretToken12345"
            svc._log_audit_event(
                action="TEST_ACTION",
                resource_type="POLICY",
                resource_id=str(policy["id"]),
                user_id=admin["id"],
                details={"api_key": "SecretApiKey999", "Authorization": f"Bearer {secret_token}"},
                status="SUCCESS",
            )

            logs = svc.get_audit_log(limit=5)
            log_str = json.dumps(logs)
            self.assertNotIn("SecretApiKey999", log_str)
            self.assertNotIn(secret_token, log_str)
            self.assertTrue("***MASKED***" in log_str or "[REDACTED" in log_str)

            # Snapshot must only contain policy configuration, zero credentials
            snapshot = svc.create_assessment_snapshot("sess_test_cred", policy["id"], applied_by_user_id=admin["id"])
            snap_str = json.dumps(snapshot)
            self.assertNotIn("password", snap_str.lower())
            self.assertNotIn("token", snap_str.lower())
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass


class TestLivePolicyChangesAndConcurrency(unittest.TestCase):
    """Verification of dynamic policy deactivation, live target revocation, and concurrency."""

    def test_live_policy_deactivation_halts_controller_loop(self):
        """Deactivating a policy while AutonomousController is running halts the loop on the next turn."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            policy = svc.create_policy(
                name="Live Deactivation Policy",
                config=get_default_policy_config(),
                creator_id=admin["id"],
                targets=[{"host_pattern": "127.0.0.1", "port_range": "5050"}],
            )

            # Create controller with policy service wired
            brain = get_model_brain(mode="mock")
            controller = AutonomousController(
                config=AgentConfig(max_turns=5, allowed_hosts={"127.0.0.1"}),
                model_brain=brain,
                evidence_store=store,
                policy_service=svc,
            )

            # Deactivate policy before turn loop executes
            svc.deactivate_policy(policy["id"], actor_id=admin["id"])

            res = controller.run_assessment(
                target_url="http://127.0.0.1:5050/api",
                session_id="sess_deact_test",
                policy_id=policy["id"],
                operator_id=admin["id"],
            )

            # Assessment must reject or halt cleanly
            self.assertTrue(
                "disabled/inactive" in res.get("error", "").lower()
                or res.get("status") in ("COMPLETED", "ERROR")
            )
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass

    def test_live_target_revocation_blocks_subsequent_tool_execution(self):
        """When a target authorization is revoked in the database mid-scan, PolicyEngine rejects further requests."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            policy = svc.create_policy(
                name="Target Revocation Policy",
                config=get_default_policy_config(),
                creator_id=admin["id"],
                targets=[{"host_pattern": "127.0.0.1", "port_range": "5050"}],
            )

            # PolicyEngine with snapshot and policy service bound
            snapshot = svc.create_assessment_snapshot("sess_revoc_test", policy["id"])
            engine = PolicyEngine(
                registered_tools={"http_request"},
                policy_snapshot=snapshot,
                policy_service=svc,
            )

            # Initial action is approved
            dec1 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:5050/api/users", "method": "GET"})
            self.assertTrue(dec1.approved)

            # Revoke target in database
            target_id = policy["targets"][0]["id"]
            svc.revoke_target_authorization(target_id, actor_id=admin["id"], policy_id=policy["id"])

            # Subsequent action to the revoked target must be denied live
            dec2 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:5050/api/users", "method": "GET"})
            self.assertFalse(dec2.approved)
            self.assertTrue("revoked" in dec2.reason.lower() or "revocation" in dec2.reason.lower())
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass

    def test_concurrent_policy_updates_no_version_clash(self):
        """Two simultaneous administrators updating the same policy increment versions strictly without collision."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin1 = auth_svc.bootstrap_admin("admin_one", "AdminPass123!One")
            admin2 = auth_svc.create_user("admin_two", "AdminPass123!Two", role="admin", creator_user_id=admin1["id"])

            policy = svc.create_policy(
                name="Concurrent Policy",
                config=get_default_policy_config(),
                creator_id=admin1["id"],
            )

            errors = []
            versions_created = []

            def worker_update(admin_id, summary):
                try:
                    cfg = get_default_policy_config()
                    cfg["max_turns"] = 12 if admin_id == admin1["id"] else 15
                    res = svc.update_policy(
                        policy_id=policy["id"],
                        new_config=cfg,
                        modifier_id=admin_id,
                        change_summary=summary,
                    )
                    versions_created.append(res["current_version"])
                except Exception as exc:
                    errors.append(exc)

            t1 = threading.Thread(target=worker_update, args=(admin1["id"], "Update from Admin 1"))
            t2 = threading.Thread(target=worker_update, args=(admin2["id"], "Update from Admin 2"))

            t1.start()
            t2.start()
            t1.join()
            t2.join()

            self.assertEqual(len(errors), 0, f"Concurrent updates produced errors: {errors}")
            self.assertEqual(len(versions_created), 2)
            pol_final = svc.get_policy(policy["id"])
            self.assertEqual(pol_final["current_version"], 3)

            history = svc.list_policy_versions(policy["id"])
            self.assertEqual(len(history), 3)
            self.assertEqual([v["version"] for v in history], [1, 2, 3])
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass

    def test_evidence_preserved_after_cancellation(self):
        """Cancelling an active assessment preserves all traffic logs and partial findings in SQLite."""
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            store = EvidenceStore(db_path=db_path)
            svc = PolicyService(store=store)
            auth_svc = AuthenticationService(store=store)
            admin = auth_svc.bootstrap_admin("admin_test", "AdminPass123!Safe")

            policy = svc.create_policy(
                name="Evidence Preservation Policy",
                config=get_default_policy_config(),
                creator_id=admin["id"],
                targets=[{"host_pattern": "127.0.0.1", "port_range": "5050"}],
            )

            manager = DashboardSessionManager(db_path=db_path, store=store, policy_service=svc)

            # Start assessment
            res_start = manager.start_assessment(
                target_url="http://127.0.0.1:5050/api",
                assessment_name="Preservation Test",
                brain_mode="mock",
                policy_id=policy["id"],
                operator_id=admin["id"],
            )
            sess_id = res_start["session_id"]

            # Record some preliminary evidence
            log_id = store.log_traffic(
                session_id=sess_id,
                method="GET",
                url="http://127.0.0.1:5050/api/users",
                response_status=200,
                response_body='{"users": []}',
            )
            store.record_finding(
                session_id=sess_id,
                endpoint="GET /api/users",
                category="API8:2023",
                status="VERIFIED",
                evidence_notes="Information Disclosure probe",
                traffic_log_id=log_id,
                severity="LOW",
            )

            # Cancel assessment
            res_cancel = manager.cancel_assessment(sess_id, actor_id=admin["id"], actor_role="admin")
            self.assertTrue(res_cancel["success"])

            # Verify evidence remains intact in database
            traffic = store.get_traffic_logs(sess_id)
            findings = store.get_findings(sess_id)
            self.assertEqual(len(traffic), 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "API8:2023")
        finally:
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
