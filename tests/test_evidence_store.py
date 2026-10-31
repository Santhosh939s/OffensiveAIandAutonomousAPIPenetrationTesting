"""Unit tests for EvidenceStore and findings verification gate."""

import unittest
from controller.storage.evidence_store import (
    EvidenceStore,
    VALID_FINDING_STATUSES,
    APPROVED_VERIFICATION_RULES,
)


class TestEvidenceStore(unittest.TestCase):
    def setUp(self):
        # Use in-memory SQLite database for isolated test execution
        self.store = EvidenceStore(db_path=":memory:")
        self.session_id = "test_sess_001"
        self.target = "http://127.0.0.1:8000"
        self.store.create_session(self.session_id, self.target, "Initial test session")

    def test_session_lifecycle(self):
        sess = self.store.get_session(self.session_id)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["session_id"], self.session_id)
        self.assertEqual(sess["target"], self.target)
        self.assertEqual(sess["status"], "ACTIVE")

        # Update session
        self.store.update_session_status(
            self.session_id,
            status="COMPLETED",
            turns_taken=3,
            requests_sent=7,
            notes="Completed successfully",
        )
        updated = self.store.get_session(self.session_id)
        self.assertEqual(updated["status"], "COMPLETED")
        self.assertEqual(updated["turns_taken"], 3)
        self.assertEqual(updated["requests_sent"], 7)

    def test_plan_storage(self):
        plan_data = {
            "plan_title": "Test Scan",
            "steps": [{"step_number": 1, "tool": "http_request", "purpose": "Recon"}],
        }
        plan_id = self.store.record_plan(self.session_id, plan_data)
        self.assertGreater(plan_id, 0)

        plans = self.store.get_plans(self.session_id)
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["plan"]["plan_title"], "Test Scan")

    def test_traffic_logging(self):
        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url="http://127.0.0.1:8000/api/users",
            headers={"Accept": "application/json"},
            request_body=None,
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='[{"id": 1, "name": "admin"}]',
            elapsed_ms=45.2,
        )
        self.assertGreater(traffic_id, 0)

        logs = self.store.get_traffic_logs(self.session_id)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["method"], "GET")
        self.assertEqual(logs[0]["response_status"], 200)

    def test_tool_execution_logging(self):
        exec_id = self.store.log_tool_execution(
            session_id=self.session_id,
            tool_name="http_request",
            arguments={"url": "http://127.0.0.1:8000/api"},
            approved=True,
            policy_reason="Authorized localhost target",
            result={"status_code": 200},
            duration_ms=50.0,
        )
        self.assertGreater(exec_id, 0)

        executions = self.store.get_tool_executions(self.session_id)
        self.assertEqual(len(executions), 1)
        self.assertTrue(executions[0]["approved"])
        self.assertEqual(executions[0]["tool_name"], "http_request")

    def test_finding_verification_gate_confirmed_success(self):
        # 1. Log valid traffic first
        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url="http://127.0.0.1:8000/items?id=1'",
            response_status=500,
            response_body="Fatal error: syntax error near '1'' in SQL statement",
        )

        # 2. Record finding with approved verification rule and traffic evidence
        f_id, assigned_status = self.store.record_finding(
            session_id=self.session_id,
            endpoint="http://127.0.0.1:8000/items",
            category="SQL Injection",
            status="CONFIRMED",
            evidence_notes="Server threw explicit SQL syntax error",
            verification_rule="SQL_SYNTAX_ERROR_MATCH",
            traffic_log_id=traffic_id,
            raw_evidence={"proof": "syntax error near"},
        )

        self.assertEqual(assigned_status, "CONFIRMED")
        findings = self.store.get_findings(self.session_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "CONFIRMED")
        self.assertEqual(findings[0]["verification_rule"], "SQL_SYNTAX_ERROR_MATCH")

    def test_finding_verification_gate_auto_demotion(self):
        # Attempt to record CONFIRMED without valid rule or evidence
        # (simulating model hallucinating a confirmed flaw without proof)
        f_id, assigned_status = self.store.record_finding(
            session_id=self.session_id,
            endpoint="http://127.0.0.1:8000/admin",
            category="RCE",
            status="CONFIRMED",
            evidence_notes="Model guessed RCE exists",
            verification_rule=None,      # No rule!
            traffic_log_id=None,         # No traffic evidence!
            raw_evidence=None,
        )

        # MUST be auto-demoted to SUSPECTED
        self.assertEqual(assigned_status, "SUSPECTED")
        findings = self.store.get_findings(self.session_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "SUSPECTED")
        self.assertIn("[AUTO-DEMOTED FROM CONFIRMED]", findings[0]["evidence_notes"])

    def test_get_traffic_by_id_and_finding_summary(self):
        traffic_id = self.store.log_traffic(
            session_id=self.session_id,
            method="GET",
            url="http://127.0.0.1:8000/api/users",
            response_status=200,
        )
        fetched = self.store.get_traffic_by_id(traffic_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], traffic_id)
        self.assertEqual(fetched["method"], "GET")

        # Record findings and check summary
        self.store.record_finding(
            session_id=self.session_id,
            endpoint="http://127.0.0.1:8000/api/users/2",
            category="BOLA / IDOR",
            status="SUSPECTED",
            evidence_notes="Potential cross-user access",
        )
        summary = self.store.get_finding_summary(self.session_id)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["by_status"]["SUSPECTED"], 1)
        self.assertEqual(summary["by_category"]["BOLA / IDOR"], 1)


if __name__ == "__main__":
    unittest.main()

