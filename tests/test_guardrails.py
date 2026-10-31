"""Unit tests for Guardrails, ScopeValidator, and PolicyEngine."""

import unittest
from controller.config import AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.guardrails.policy_engine import PolicyEngine


class TestScopeValidator(unittest.TestCase):
    def setUp(self):
        self.config = AgentConfig()
        self.validator = ScopeValidator(self.config)

    def test_valid_localhost_urls(self):
        valid_urls = [
            "http://127.0.0.1:8000/api/v1/users",
            "http://localhost:5000/test",
            "https://127.0.0.1/",
            "http://localhost/",
        ]
        for url in valid_urls:
            res = self.validator.validate_url(url)
            self.assertTrue(res.is_valid, f"Expected {url} to be valid: {res.reason}")
            self.assertIsNotNone(res.normalized_url)

    def test_rejected_external_targets(self):
        external_urls = [
            "http://example.com/api",
            "https://api.github.com/repos",
            "http://8.8.8.8/api/dns",
            "http://93.184.216.34/",
        ]
        for url in external_urls:
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_valid, f"Expected {url} to be rejected: {res.reason}")
            self.assertIn("out of scope", res.reason.lower())

    def test_rejected_cloud_metadata(self):
        metadata_url = "http://169.254.169.254/latest/meta-data/"
        res = self.validator.validate_url(metadata_url)
        self.assertFalse(res.is_valid)
        self.assertIn("blocked ip", res.reason.lower())

    def test_rejected_schemes(self):
        invalid_schemes = [
            "ftp://127.0.0.1/test",
            "file:///etc/passwd",
            "gopher://127.0.0.1:70",
        ]
        for url in invalid_schemes:
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_valid)
            self.assertIn("prohibited", res.reason.lower())

    def test_empty_or_malformed_url(self):
        for bad in ["", None, "   ", 123]:
            res = self.validator.validate_url(bad)
            self.assertFalse(res.is_valid)


class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.config = AgentConfig(max_requests_per_session=5)
        self.engine = PolicyEngine(
            config=self.config,
            registered_tools={"http_request", "jwt_inspector", "parameter_fuzzer"},
        )

    def test_unregistered_tool_rejected(self):
        decision = self.engine.evaluate_action(
            tool_name="arbitrary_bash_executor",
            arguments={"cmd": "whoami"},
        )
        self.assertFalse(decision.approved)
        self.assertIn("not in the authorized tool registry", decision.reason)

    def test_valid_http_request_approved(self):
        decision = self.engine.evaluate_action(
            tool_name="http_request",
            arguments={"url": "http://127.0.0.1:8000/api", "method": "GET"},
        )
        self.assertTrue(decision.approved)

    def test_http_request_scope_violation_rejected(self):
        decision = self.engine.evaluate_action(
            tool_name="http_request",
            arguments={"url": "http://public-target.com/api", "method": "GET"},
        )
        self.assertFalse(decision.approved)
        self.assertIn("scope violation", decision.reason.lower())

    def test_destructive_sql_query_rejected(self):
        decision = self.engine.evaluate_action(
            tool_name="http_request",
            arguments={
                "url": "http://127.0.0.1:8000/api/users",
                "method": "POST",
                "body": "DROP TABLE users;",
            },
        )
        self.assertFalse(decision.approved)
        self.assertIn("destructive database operation", decision.reason.lower())

    def test_request_budget_limit_enforced(self):
        # Budget is 5 requests
        decision = self.engine.evaluate_action(
            tool_name="http_request",
            arguments={"url": "http://127.0.0.1:8000/api", "method": "GET"},
            current_request_count=5,
        )
        self.assertFalse(decision.approved)
        self.assertIn("cumulative request limit reached", decision.reason.lower())

    def test_jwt_inspector_validation(self):
        # Empty token rejected
        decision = self.engine.evaluate_action(
            tool_name="jwt_inspector",
            arguments={"token": ""},
        )
        self.assertFalse(decision.approved)

        # Valid string approved
        decision = self.engine.evaluate_action(
            tool_name="jwt_inspector",
            arguments={"token": "abc.def.ghi"},
        )
        self.assertTrue(decision.approved)


if __name__ == "__main__":
    unittest.main()

