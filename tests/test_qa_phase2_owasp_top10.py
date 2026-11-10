"""QA Phase 2: Comprehensive OWASP API Top 10 (2023) Validation & Baseline Assurance.

Validates the full coverage of all 10 OWASP API Security Top 10 categories against
the controlled local laboratory environment, ensuring:
1. API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
2. API2:2023 - Broken Authentication (Weak Auth / 'none' JWT)
3. API3:2023 - Broken Object Property Level Authorization (BOPLA / Mass Assignment)
4. API4:2023 - Unrestricted Resource Consumption
5. API5:2023 - Broken Function Level Authorization (BFLA)
6. API6:2023 - Unrestricted Access to Sensitive Business Flows
7. API7:2023 - Server-Side Request Forgery (SSRF)
8. API8:2023 - Security Misconfiguration (SQL Injection & GraphQL Introspection)
9. API9:2023 - Improper Inventory Management (Shadow / Deprecated API)
10. API10:2023 - Unsafe Consumption of APIs (Downstream Webhook Ingestion)

Additionally verifies:
- Baseline safe endpoints (/health, /api/items) do not trigger false-positive CONFIRMED findings.
- Auto-demotion from CONFIRMED to SUSPECTED when verification rule or traffic evidence is missing.
- Consistency of CVSS v3.1 scoring, CWE identifiers, technical impact descriptions, and reproduction steps.
"""

import json
import socket
import threading
import time
import unittest
from typing import ClassVar, Any

import httpx
from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from controller.storage.evidence_store import EvidenceStore, APPROVED_VERIFICATION_RULES
from controller.reporting.risk_engine import RiskAssessmentEngine, FindingRiskProfile, Severity


class TestQAPhase2OWASPTop10(unittest.TestCase):
    """QA Phase 2: Systematic validation of all 10 OWASP API Security Top 10 categories."""

    server: ClassVar[Any] = None
    server_thread: ClassVar[threading.Thread] = None
    target_url: ClassVar[str] = ""
    port: ClassVar[int] = 0

    @classmethod
    def setUpClass(cls):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        db = LabDatabase(":memory:")
        app = create_app(db)
        cls.server = make_server("127.0.0.1", cls.port, app)
        cls.target_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_id = f"sess_qa_owasp_{int(time.time() * 1000)}"
        self.store.create_session(self.session_id, self.target_url, "QA Phase 2 OWASP Top 10 Run")

    # -------------------------------------------------------------------------
    # 1. API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
    # -------------------------------------------------------------------------
    def test_owasp_api1_bola_idor_detection_and_verification(self):
        """API1: Accessing Bob's user details (id 2) or order (id 102) without ownership check."""
        resp = httpx.get(f"{self.target_url}/api/users/2", timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["username"], "bob")
        self.assertIn("password_hash", data)

        # Log traffic
        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url=f"{self.target_url}/api/users/2",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/users/2",
            category="BOLA / IDOR",
            status="CONFIRMED",
            evidence_notes="Cross-account data accessed: user record contains private password hash and token without authorization",
            verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )

        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-639")
        self.assertEqual(f["severity"], "HIGH")
        self.assertGreaterEqual(f["cvss_score"], 8.0)

    # -------------------------------------------------------------------------
    # 2. API2:2023 - Broken Authentication
    # -------------------------------------------------------------------------
    def test_owasp_api2_broken_authentication_and_none_jwt(self):
        """API2: Empty password bypass and unsigned JWT with header alg='none'."""
        resp = httpx.post(f"{self.target_url}/api/login", json={"username": "admin", "password": ""}, timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        token = data["token"]

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="POST",
            url=f"{self.target_url}/api/login",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/login",
            category="Insecure JWT",
            status="CONFIRMED",
            evidence_notes=f"Issued token has alg='none' and accepted empty password bypass: {token[:20]}...",
            verification_rule="TOKEN_ALGORITHM_NONE_ACCEPTED",
            traffic_log_id=traffic_id,
            raw_evidence={"token": token},
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-347")
        self.assertEqual(f["severity"], "HIGH")

    # -------------------------------------------------------------------------
    # 3. API3:2023 - Broken Object Property Level Authorization (BOPLA)
    # -------------------------------------------------------------------------
    def test_owasp_api3_bopla_mass_assignment(self):
        """API3: Updating user profile to elevate to admin role via mass assignment."""
        resp = httpx.put(f"{self.target_url}/api/users/1", json={"role": "admin", "is_admin": 1}, timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["role"], "admin")

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="PUT",
            url=f"{self.target_url}/api/users/1",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/users/1",
            category="Mass Assignment",
            status="CONFIRMED",
            evidence_notes="Privilege escalation via mass assignment: updated 'role' to admin successfully",
            verification_rule="ROLE_ELEVATION_VERIFIED",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-915")
        self.assertEqual(f["severity"], "HIGH")

    # -------------------------------------------------------------------------
    # 4. API4:2023 - Unrestricted Resource Consumption
    # -------------------------------------------------------------------------
    def test_owasp_api4_unrestricted_resource_consumption(self):
        """API4: Unbounded batch limit requested with no pagination ceiling."""
        resp = httpx.get(f"{self.target_url}/api/items/batch?limit=50000", timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("unrestricted_resource_consumption"))
        self.assertFalse(data.get("max_ceiling_enforced"))

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url=f"{self.target_url}/api/items/batch?limit=50000",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/items/batch",
            category="Unrestricted Resource Consumption",
            status="CONFIRMED",
            evidence_notes="Endpoint accepted limit=50000 without pagination limit or rate throttling",
            verification_rule="UNRESTRICTED_RESOURCE_CONSUMPTION",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-770")
        self.assertEqual(f["severity"], "MEDIUM")

    # -------------------------------------------------------------------------
    # 5. API5:2023 - Broken Function Level Authorization (BFLA)
    # -------------------------------------------------------------------------
    def test_owasp_api5_bfla_administrative_bypass(self):
        """API5: Sensitive administrative export invoked without auth check."""
        resp = httpx.get(f"{self.target_url}/api/admin/export", timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("bfla_exposed"))
        self.assertIn("users", data)

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url=f"{self.target_url}/api/admin/export",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/admin/export",
            category="Broken Function Level Authorization",
            status="CONFIRMED",
            evidence_notes="Administrative export endpoint returned database dump without authorization credentials",
            verification_rule="BFLA_ADMIN_FUNCTION_BYPASS",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-285")
        self.assertEqual(f["severity"], "HIGH")

    # -------------------------------------------------------------------------
    # 6. API6:2023 - Unrestricted Access to Sensitive Business Flows
    # -------------------------------------------------------------------------
    def test_owasp_api6_sensitive_business_flow_abuse(self):
        """API6: Repeated coupon application without velocity/quota controls."""
        resp = httpx.post(
            f"{self.target_url}/api/coupons/apply",
            json={"coupon_code": "SAVE50", "order_id": 101},
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("business_flow_abuse"))

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="POST",
            url=f"{self.target_url}/api/coupons/apply",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/coupons/apply",
            category="Unrestricted Access to Sensitive Business Flows",
            status="CONFIRMED",
            evidence_notes="Coupon redemption flow allowed unthrottled reuse without per-account ceiling",
            verification_rule="BUSINESS_FLOW_UNRESTRICTED_ACCESS",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-799")
        self.assertEqual(f["severity"], "MEDIUM")

    # -------------------------------------------------------------------------
    # 7. API7:2023 - Server-Side Request Forgery (SSRF)
    # -------------------------------------------------------------------------
    def test_owasp_api7_ssrf_detection_and_verification(self):
        """API7: Arbitrary outbound URL dispatched to loopback/internal resource."""
        target_internal = "http://127.0.0.1:5000/api/admin/export"
        resp = httpx.post(
            f"{self.target_url}/api/integrations/fetch",
            json={"url": target_internal},
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("ssrf_exposed"))

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="POST",
            url=f"{self.target_url}/api/integrations/fetch",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/integrations/fetch",
            category="SSRF",
            status="CONFIRMED",
            evidence_notes=f"Server allowed outbound fetch to private internal target: {target_internal}",
            verification_rule="SSRF_INTERNAL_ENDPOINT_LEAK",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-918")
        self.assertEqual(f["severity"], "HIGH")

    # -------------------------------------------------------------------------
    # 8. API8:2023 - Security Misconfiguration (SQL Injection & GraphQL)
    # -------------------------------------------------------------------------
    def test_owasp_api8_sql_injection_and_graphql_misconfiguration(self):
        """API8: SQL syntax error leak and GraphQL introspection exposure."""
        # 8a: SQL Injection
        resp_sql = httpx.get(f"{self.target_url}/api/search?q='", timeout=5.0)
        self.assertEqual(resp_sql.status_code, 500)
        sql_err = resp_sql.json()
        self.assertIn("syntax error", sql_err.get("error", "").lower())

        traffic_id_sql = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url=f"{self.target_url}/api/search?q='",
            response_status=500,
            response_body=resp_sql.text,
        )

        fid_sql, status_sql = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/search",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="Explicit SQLite operational syntax error leaked in 500 response body",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            traffic_log_id=traffic_id_sql,
            raw_evidence=sql_err,
        )
        self.assertEqual(status_sql, "CONFIRMED")

        # 8b: GraphQL Introspection
        resp_gql = httpx.post(
            f"{self.target_url}/graphql",
            json={"query": "{ __schema { types { name } } }"},
            timeout=5.0,
        )
        self.assertEqual(resp_gql.status_code, 200)
        gql_data = resp_gql.json()
        self.assertIn("__schema", gql_data.get("data", {}))

        traffic_id_gql = self.store.log_traffic(
            session_id=self.session_id,
            method="POST",
            url=f"{self.target_url}/graphql",
            response_status=200,
            response_body=resp_gql.text,
        )

        fid_gql, status_gql = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/graphql",
            category="GraphQL Introspection Enabled",
            status="CONFIRMED",
            evidence_notes="GraphQL schema introspection query successfully exposed system types",
            verification_rule="GRAPHQL_INTROSPECTION_EXPOSED",
            traffic_log_id=traffic_id_gql,
            raw_evidence=gql_data,
        )
        self.assertEqual(status_gql, "CONFIRMED")

        findings = self.store.get_findings(self.session_id)
        f_sql = next(x for x in findings if x["id"] == fid_sql)
        self.assertEqual(f_sql["cwe_id"], "CWE-89")
        self.assertEqual(f_sql["severity"], "CRITICAL")

        f_gql = next(x for x in findings if x["id"] == fid_gql)
        self.assertEqual(f_gql["cwe_id"], "CWE-16")
        self.assertEqual(f_gql["severity"], "LOW")

    # -------------------------------------------------------------------------
    # 9. API9:2023 - Improper Inventory Management
    # -------------------------------------------------------------------------
    def test_owasp_api9_improper_inventory_shadow_api(self):
        """API9: Deprecated shadow API endpoint active and accessible."""
        resp = httpx.get(f"{self.target_url}/api/v1/users/export", timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("shadow_api"))
        self.assertEqual(data.get("version"), "v1.0-deprecated")

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url=f"{self.target_url}/api/v1/users/export",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/v1/users/export",
            category="Improper Inventory Management",
            status="CONFIRMED",
            evidence_notes="Deprecated v1.0 API accessible without authentication exposing unredacted records",
            verification_rule="SHADOW_OR_DEPRECATED_API_EXPOSED",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-1059")
        self.assertEqual(f["severity"], "MEDIUM")

    # -------------------------------------------------------------------------
    # 10. API10:2023 - Unsafe Consumption of APIs
    # -------------------------------------------------------------------------
    def test_owasp_api10_unsafe_consumption_of_apis(self):
        """API10: Ingesting third-party partner callback without signature check."""
        resp = httpx.post(
            f"{self.target_url}/api/integrations/webhook",
            json={"partner_name": "payment_gateway", "event": "transfer", "payload": {"amount": 1000}},
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("unsafe_consumption"))
        self.assertFalse(data.get("signature_verified"))

        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="POST",
            url=f"{self.target_url}/api/integrations/webhook",
            response_status=resp.status_code,
            response_body=resp.text,
        )

        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/integrations/webhook",
            category="Unsafe Consumption of APIs",
            status="CONFIRMED",
            evidence_notes="Webhook processed downstream payload without HMAC cryptographic signature verification",
            verification_rule="UNSAFE_DOWNSTREAM_API_CONSUMPTION",
            traffic_log_id=traffic_id,
            raw_evidence=data,
        )
        self.assertEqual(status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        f = next(x for x in findings if x["id"] == fid)
        self.assertEqual(f["cwe_id"], "CWE-20")
        self.assertEqual(f["severity"], "HIGH")

    # -------------------------------------------------------------------------
    # 11. Baseline Safe Endpoints & False Positive Demotion Checks
    # -------------------------------------------------------------------------
    def test_baseline_safe_endpoints_not_confirmed(self):
        """Ensure safe baseline endpoints (/health and /api/items) behave properly."""
        # 1. Health check returns 200 clean
        h_resp = httpx.get(f"{self.target_url}/health", timeout=5.0)
        self.assertEqual(h_resp.status_code, 200)
        self.assertEqual(h_resp.json().get("status"), "healthy")

        # 2. Items catalog returns 200 clean
        i_resp = httpx.get(f"{self.target_url}/api/items", timeout=5.0)
        self.assertEqual(i_resp.status_code, 200)
        self.assertGreaterEqual(i_resp.json().get("count", 0), 1)

        # Baseline traffic log
        t_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url=f"{self.target_url}/health",
            response_status=200,
            response_body=h_resp.text,
        )

        # Baseline evaluation recorded as NOT_DEMONSTRATED
        fid, status = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/health",
            category="Health Check Baseline",
            status="NOT_DEMONSTRATED",
            evidence_notes="Endpoint returned valid service status, no security vulnerability identified",
            verification_rule=None,
            traffic_log_id=t_id,
        )
        self.assertEqual(status, "NOT_DEMONSTRATED")

    def test_auto_demotion_gate_without_valid_rule_or_evidence(self):
        """Invariant: findings cannot be CONFIRMED without approved rule and traffic evidence."""
        # Case A: Missing approved rule -> demoted to SUSPECTED
        fid_a, status_a = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/test",
            category="Custom Alert",
            status="CONFIRMED",
            evidence_notes="Model claimed vulnerability without approved verification gate",
            verification_rule="NON_EXISTENT_RULE",
            traffic_log_id=1,
            raw_evidence={"dummy": True},
        )
        self.assertEqual(status_a, "SUSPECTED")
        findings = self.store.get_findings(self.session_id)
        fa = next(x for x in findings if x["id"] == fid_a)
        self.assertIn("[AUTO-DEMOTED FROM CONFIRMED]", fa["evidence_notes"])

        # Case B: Missing traffic log AND raw evidence -> demoted to SUSPECTED
        fid_b, status_b = self.store.record_finding(
            session_id=self.session_id,
            endpoint=f"{self.target_url}/api/test",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="Asserted without traffic receipt",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            traffic_log_id=None,
            raw_evidence=None,
        )
        self.assertEqual(status_b, "SUSPECTED")
        findings_b = self.store.get_findings(self.session_id)
        fb = next(x for x in findings_b if x["id"] == fid_b)
        self.assertIn("[AUTO-DEMOTED FROM CONFIRMED]", fb["evidence_notes"])

    # -------------------------------------------------------------------------
    # 12. Quality Verification: Impact & Safe Reproduction Steps Across All 10
    # -------------------------------------------------------------------------
    def test_all_10_owasp_categories_have_impact_and_reproduction(self):
        """Verify that every OWASP API category returns high-quality risk profiles."""
        categories = [
            ("API1", "BOLA / IDOR"),
            ("API2", "Insecure JWT"),
            ("API3", "Mass Assignment"),
            ("API4", "Unrestricted Resource Consumption"),
            ("API5", "Broken Function Level Authorization"),
            ("API6", "Unrestricted Access to Sensitive Business Flows"),
            ("API7", "SSRF"),
            ("API8", "SQL Injection"),
            ("API9", "Improper Inventory Management"),
            ("API10", "Unsafe Consumption of APIs"),
        ]

        for code, cat in categories:
            profile = RiskAssessmentEngine.get_finding_risk_profile(
                category=cat,
                status="CONFIRMED",
                endpoint=f"{self.target_url}/api/endpoint",
            )
            self.assertIsInstance(profile, FindingRiskProfile)
            self.assertTrue(profile.technical_impact, f"Missing impact for {code} {cat}")
            self.assertTrue(profile.reproduction_steps, f"Missing reproduction for {code} {cat}")
            self.assertTrue(profile.remediation_guidance, f"Missing remediation for {code} {cat}")
            self.assertIn("CWE-", profile.cwe_id)
            self.assertGreater(profile.cvss_score, 0.0)


if __name__ == "__main__":
    unittest.main()
