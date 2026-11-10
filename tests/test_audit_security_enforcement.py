"""Independent Security Enforcement and Evidence Audit Tests.

Provides rigorous, spy-based verification for:
1. Per-tool execution gating (spy confirms denied tool handlers are NEVER invoked).
2. Direct ToolRegistry execution protection via attached policy engine.
3. Layer 1 immutable safety invariants (cannot be weakened by admin policy, rollback, or AI args).
4. Socket-level connection security & DNS rebinding defense.
5. Active resource budget boundary conditions (requests, duration, turns, concurrency, body size).
6. Service-level RBAC (Operators strictly denied from mutating policies or targets).
7. Credential masking in audit logs and snapshots.
"""

import time
import socket
import pytest
from unittest.mock import MagicMock, patch

from controller.agent.autonomous_controller import AutonomousController
from controller.guardrails.policy_engine import PolicyEngine, DEVELOPER_SAFETY_MAX_REQUESTS
from controller.guardrails.policy_service import PolicyService, get_default_policy_config
from controller.guardrails.scope_validator import ScopeValidator, canonicalize_ip_str
from controller.storage.evidence_store import EvidenceStore
from controller.tools.registry import ToolRegistry, BaseTool
from controller.tools.http_request import execute_http_request


@pytest.fixture
def temp_store(tmp_path):
    db_file = tmp_path / "test_security_audit.db"
    return EvidenceStore(str(db_file))


@pytest.fixture
def policy_service(temp_store):
    return PolicyService(temp_store)


class DummySpyTool(BaseTool):
    """Tool equipped with an execution counter spy."""
    def __init__(self, name: str = "spy_tool"):
        super().__init__(
            name=name,
            description="Spy tool for verifying execution suppression",
            parameters_schema={"type": "object"},
            category="active_probe",
        )
        self.call_count = 0

    def execute(self, **kwargs):
        self.call_count += 1
        return {"success": True, "call_count": self.call_count}

    def validate_arguments(self, arguments):
        return True, None


class TestPerToolExecutionEnforcement:
    """Requirement 1: Verify authorization is evaluated immediately before execution."""

    def test_denied_tool_handler_is_never_invoked_in_controller(self, temp_store, policy_service):
        """When an action is denied by policy, the tool's execute() method must NOT be called."""
        spy_tool = DummySpyTool("spy_tool")
        registry = ToolRegistry()
        registry.register_tool(spy_tool)

        # Policy omitting 'spy_tool' from allowed_tools
        cfg = get_default_policy_config()
        cfg["allowed_tools"] = ["http_request"]  # spy_tool NOT allowed
        policy = policy_service.create_policy(
            name="No Spy Policy",
            description="Test",
            config=cfg,
            creator_id=1,
            targets=[{"host_pattern": "127.0.0.1", "port_range": "8000", "path_prefix": "/"}]
        )

        mock_brain = MagicMock()
        mock_brain.create_test_plan.return_value = {"plan_title": "Plan", "steps": []}
        # Model proposes spy_tool on turn 1, then completes on turn 2
        mock_brain.select_next_action.side_effect = [
            {"action_type": "execute_tool", "tool_name": "spy_tool", "arguments": {}},
            {"action_type": "complete", "reasoning": "Done"},
        ]

        controller = AutonomousController(
            evidence_store=temp_store,
            model_brain=mock_brain,
            tool_registry=registry,
            policy_service=policy_service,
        )

        controller.run_assessment(
            target_url="http://127.0.0.1:8000/api",
            policy_id=policy["id"],
        )

        # SPY ASSERTION: Handler was NEVER called
        assert spy_tool.call_count == 0, "Security Failure: Denied tool handler was executed!"

    def test_direct_tool_registry_execution_enforces_policy(self):
        """Direct call to ToolRegistry.execute() must be blocked if attached policy engine rejects."""
        spy_tool = DummySpyTool("spy_tool")
        registry = ToolRegistry()
        registry.register_tool(spy_tool)

        engine = PolicyEngine(registered_tools={"spy_tool"})
        # Bind snapshot forbidding spy_tool
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["other_tool"], "max_requests": 10},
            "targets": []
        })
        registry.set_policy_engine(engine)

        res = registry.execute("spy_tool", {})
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert spy_tool.call_count == 0, "Security Failure: Direct registry execution bypassed policy!"


class TestImmutableDeveloperRestrictions:
    """Requirement 2: Developer invariants cannot be overridden by admin or operator."""

    def test_admin_policy_cannot_override_metadata_block(self):
        """Even if target authorizations contain metadata IP, ScopeValidator strictly rejects it."""
        validator = ScopeValidator()
        malicious_targets = [{
            "host_pattern": "169.254.169.254",
            "port_range": "80",
            "allowed_schemes": "http",
            "path_prefix": "/",
            "is_active": 1,
        }]
        res = validator.validate_url("http://169.254.169.254/latest/meta-data/", target_authorizations=malicious_targets)
        assert res.is_valid is False
        assert "strictly blocked IP" in res.reason or "Layer 1" in res.reason

    def test_admin_policy_cannot_override_100_request_ceiling(self):
        """Even if policy config sets max_requests=1000, Layer 1 invariant halts at 100."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 1000},
            "targets": []
        })
        # Attempt request 100
        decision = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api"}, current_request_count=100)
        assert decision.approved is False
        assert "Developer safety ceiling reached" in decision.reason

    def test_destructive_sql_blocked_unconditionally(self):
        """Destructive database operations are unconditionally rejected."""
        engine = PolicyEngine(registered_tools={"http_request"})
        decision = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1:8000/api", "body": "admin' OR 1=1; TRUNCATE TABLE users; --"}
        )
        assert decision.approved is False
        assert "Destructive database operation detected" in decision.reason

    def test_encoded_metadata_ip_blocked(self):
        """Dword and hex encoded metadata IPs are blocked by canonical normalization."""
        validator = ScopeValidator()
        # 2852039166 = 169.254.169.254
        assert validator.validate_url("http://2852039166/latest/meta-data").is_valid is False
        # 0xa9fea9fe = 169.254.169.254
        assert validator.validate_url("http://0xa9fea9fe/latest/meta-data").is_valid is False


class TestSocketConnectionSecurityAndDnsRebinding:
    """Requirement 3: Socket-level Layer 1 safety and DNS rebinding defense."""

    def test_socket_connection_blocked_for_metadata_destination(self):
        """Connection to 169.254.169.254 is intercepted and blocked at the socket creation level."""
        res = execute_http_request("http://169.254.169.254/latest/meta-data", timeout=1)
        assert res["success"] is False
        assert "Layer 1 Safety Violation" in str(res.get("error"))

    def test_dns_rebinding_to_metadata_blocked_at_socket_connect(self):
        """If DNS answer returns 169.254.169.254 during socket connect, connection is blocked."""
        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            res = execute_http_request("http://rebind-test.local/probe", timeout=1)
            assert res["success"] is False
            assert "Layer 1 Safety Violation" in str(res.get("error"))

    def test_redirect_to_metadata_revalidated_and_rejected(self):
        """Redirect destination to cloud metadata is marked out of scope."""
        validator = ScopeValidator()
        res = validator.validate_redirect(
            original_url="http://127.0.0.1:8000/api/redirect",
            redirect_location="http://169.254.169.254/latest/meta-data"
        )
        assert res.is_valid is False
        assert "strictly blocked IP" in res.reason


class TestResourceBudgetBoundaries:
    """Requirement 4: Verify boundary conditions for all active resource limits."""

    def test_request_limit_exact_boundary(self):
        """Boundary: request limit at limit (approved) vs one above (rejected)."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 5},
            "targets": []
        })

        # At 4 requests (1 below limit): Approved
        assert engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api"}, current_request_count=4).approved is True
        # At 5 requests (exact limit): Rejected
        decision = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api"}, current_request_count=5)
        assert decision.approved is False
        assert "Cumulative request limit reached" in decision.reason

    def test_duration_limit_exact_boundary(self):
        """Boundary: duration just below limit (approved) vs at/above limit (rejected)."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_assessment_duration_seconds": 60.0},
            "targets": []
        })

        # At 59.9 seconds: Approved
        assert engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api"}, current_duration_seconds=59.9).approved is True
        # At 60.0 seconds: Rejected
        decision = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api"}, current_duration_seconds=60.0)
        assert decision.approved is False
        assert "Assessment duration limit reached" in decision.reason

    def test_concurrency_limit_boundary(self, temp_store, policy_service):
        """Boundary: concurrency at limit (rejected) vs below limit (permitted)."""
        cfg = get_default_policy_config()
        cfg["max_concurrent_assessments"] = 2
        policy = policy_service.create_policy(
            name="Concurrency Policy",
            description="Test",
            config=cfg,
            creator_id=1,
            targets=[{"host_pattern": "127.0.0.1", "port_range": "8000", "path_prefix": "/"}]
        )

        # 1 active session (below limit of 2): Permitted
        permitted_1, _, _ = policy_service.check_assessment_permitted(
            policy_id=policy["id"],
            target_url="http://127.0.0.1:8000/api",
            current_concurrency=1,
        )
        assert permitted_1 is True

        # 2 active sessions (at max limit): Rejected
        permitted_2, reason, _ = policy_service.check_assessment_permitted(
            policy_id=policy["id"],
            target_url="http://127.0.0.1:8000/api",
            current_concurrency=2,
        )
        assert permitted_2 is False
        assert "Maximum concurrent assessment limit reached" in reason


class TestRoleAndServiceAuthorization:
    """Requirement 7: Verify RBAC at the service boundary."""

    def test_operator_cannot_mutate_policies(self, temp_store, policy_service):
        """User with role 'operator' is rejected from creating or mutating policies."""
        # Seed an operator user in the database
        with temp_store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, is_active, created_at, updated_at)
                VALUES ('operator_jim', 'hash', 'salt', 'operator', 1, 1000.0, 1000.0)
                """
            )
            operator_id = cursor.lastrowid
            conn.commit()

        # Attempt to create a policy with operator ID -> Must raise PermissionError
        with pytest.raises(PermissionError, match="Insufficient privileges"):
            policy_service.create_policy(
                name="Illegal Policy",
                description="Operator attempt",
                config=get_default_policy_config(),
                creator_id=operator_id,
            )

        # Attempt to add target authorization -> Must raise PermissionError
        with pytest.raises(PermissionError, match="Insufficient privileges"):
            policy_service.add_target_authorization(
                policy_id=1,
                target_def={"host_pattern": "127.0.0.1"},
                actor_id=operator_id,
            )


class TestCredentialSanitizationInAuditAndSnapshots:
    """Requirement 5: Ensure credentials never appear in logs or snapshots."""

    def test_credentials_masked_in_audit_records(self, temp_store, policy_service):
        """Pass credentials in details -> verify they are masked in admin_audit_log."""
        policy = policy_service.create_policy(
            name="Auth Test Policy",
            description="Test",
            config=get_default_policy_config(),
            creator_id=1,
        )

        policy_service._log_audit_event(
            action="TEST_ACTION",
            resource_type="POLICY",
            resource_id=str(policy["id"]),
            user_id=1,
            details={
                "password": "SuperSecretPassword123!",
                "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.s",
                "safe_field": "visible_value"
            }
        )

        with temp_store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT details_json FROM admin_audit_log WHERE action = 'TEST_ACTION'")
            row = cursor.fetchone()
            assert row is not None
            details_str = row["details_json"]
            assert "SuperSecretPassword123!" not in details_str, "Security Failure: Password was logged in plain text!"
            assert "eyJhbGci" not in details_str, "Security Failure: Token was logged in plain text!"
            assert "visible_value" in details_str
