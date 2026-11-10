"""Tests for End-to-End Policy Enforcement.

Validates deterministic enforcement of Layer 1 safety invariants and Layer 2
policy snapshots through PolicyEngine and AutonomousController.
"""

import tempfile
import os
import pytest
from unittest.mock import MagicMock

from controller.agent.autonomous_controller import AutonomousController
from controller.guardrails.policy_engine import PolicyEngine, PolicyDecision
from controller.guardrails.policy_service import PolicyService, get_default_policy_config
from controller.storage.evidence_store import EvidenceStore
from controller.tools import ToolRegistry, build_default_tool_registry


@pytest.fixture
def temp_store(tmp_path):
    db_file = tmp_path / "test_enforcement.db"
    return EvidenceStore(str(db_file))


@pytest.fixture
def policy_service(temp_store):
    return PolicyService(temp_store)


class TestPolicyEngineSnapshotEnforcement:
    """Verify PolicyEngine behavior when guided by an active snapshot."""

    def test_tool_whitelist_rejection(self):
        """Tool not in allowed_tools is rejected by Layer 2 policy."""
        tools = {"http_request", "jwt_inspector", "openapi_parser"}
        engine = PolicyEngine(registered_tools=tools)

        snapshot = {
            "policy_id": 1,
            "config": {
                "allowed_tools": ["http_request", "openapi_parser"],  # jwt_inspector omitted
                "max_requests": 20,
            },
            "targets": [],
        }
        engine.bind_policy_snapshot(snapshot)

        # http_request is permitted
        decision_http = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api", "method": "GET"})
        assert decision_http.approved is True

        # jwt_inspector is in registered_tools but disallowed by policy snapshot
        decision_jwt = engine.evaluate_action("jwt_inspector", {"token": "eyJhbGciOiJIUzI1NiJ9.e30.x"})
        assert decision_jwt.approved is False
        assert "not permitted by active policy" in decision_jwt.reason

    def test_http_method_restriction(self):
        """HTTP method not in policy allowed_http_methods is rejected."""
        tools = {"http_request"}
        engine = PolicyEngine(registered_tools=tools)

        snapshot = {
            "policy_id": 1,
            "config": {
                "allowed_tools": ["http_request"],
                "allowed_http_methods": ["GET", "HEAD"],  # POST/DELETE disallowed
                "max_requests": 20,
            },
            "targets": [],
        }
        engine.bind_policy_snapshot(snapshot)

        # GET is allowed
        res_get = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api", "method": "GET"})
        assert res_get.approved is True

        # DELETE is rejected
        res_del = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api", "method": "DELETE"})
        assert res_del.approved is False
        assert "is not allowed by policy" in res_del.reason

    def test_policy_request_limit_enforced(self):
        """Reaching policy max_requests exhausts session budget."""
        tools = {"http_request"}
        engine = PolicyEngine(registered_tools=tools)

        snapshot = {
            "policy_id": 1,
            "config": {
                "allowed_tools": ["http_request"],
                "max_requests": 5,
            },
            "targets": [],
        }
        engine.bind_policy_snapshot(snapshot)

        # At count 4, action is approved
        res_ok = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api", "method": "GET"}, current_request_count=4)
        assert res_ok.approved is True

        # At count 5, action is rejected
        res_exhausted = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api", "method": "GET"}, current_request_count=5)
        assert res_exhausted.approved is False
        assert "Cumulative request limit reached" in res_exhausted.reason

    def test_layer1_developer_safety_ceiling_preempts_policy(self):
        """Even if policy specifies 500 requests, Layer 1 enforces the 100 limit."""
        tools = {"http_request"}
        engine = PolicyEngine(registered_tools=tools)

        snapshot = {
            "policy_id": 1,
            "config": {
                "allowed_tools": ["http_request"],
                "max_requests": 500,  # Invalid high limit in raw snapshot
            },
            "targets": [],
        }
        engine.bind_policy_snapshot(snapshot)

        # At count 100, Layer 1 safety ceiling terminates
        res = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api", "method": "GET"}, current_request_count=100)
        assert res.approved is False
        assert "Developer safety ceiling reached" in res.reason

    def test_layer1_destructive_db_pattern_blocked(self):
        """Destructive database operations are unconditionally blocked by Layer 1."""
        tools = {"http_request"}
        engine = PolicyEngine(registered_tools=tools)

        res = engine.evaluate_action(
            "http_request",
            {
                "url": "http://127.0.0.1:8000/api/users",
                "method": "POST",
                "body": "1; DROP TABLE users; --",
            }
        )
        assert res.approved is False
        assert "Destructive database operation detected" in res.reason


class TestAutonomousControllerPolicyIntegration:
    """Verify AutonomousController interaction with PolicyService and snapshots."""

    def test_controller_permits_authorized_assessment(self, policy_service, temp_store):
        """Assessment for authorized target launches and creates frozen snapshot."""
        policy = policy_service.create_policy(
            name="Authorized App Policy",
            description="Policy allowing test app",
            config=get_default_policy_config(),
            creator_id=1,
            targets=[{
                "host_pattern": "127.0.0.1",
                "port_range": "8000",
                "allowed_schemes": "http",
                "path_prefix": "/api",
            }]
        )

        mock_brain = MagicMock()
        mock_brain.create_test_plan.return_value = {"plan_title": "Test Plan", "steps": []}
        mock_brain.select_next_action.return_value = {"action_type": "complete", "reasoning": "Done testing"}

        controller = AutonomousController(
            evidence_store=temp_store,
            model_brain=mock_brain,
            policy_service=policy_service,
        )

        result = controller.run_assessment(
            target_url="http://127.0.0.1:8000/api/v1",
            policy_id=policy["id"],
            operator_id=1,
        )

        assert result["success"] is True
        session_id = result["session_id"]
        assert session_id is not None

        # Verify assessment snapshot was stored
        snapshot = policy_service.get_assessment_snapshot(session_id)
        assert snapshot is not None
        assert snapshot["policy_id"] == policy["id"]
        assert snapshot["policy_version"] == 1

    def test_controller_rejects_unauthorized_target_before_session(self, policy_service, temp_store):
        """Assessment for unauthorized target is rejected before session creation."""
        policy = policy_service.create_policy(
            name="Restricted App Policy",
            description="Allows port 8080 only",
            config=get_default_policy_config(),
            creator_id=1,
            targets=[{
                "host_pattern": "127.0.0.1",
                "port_range": "8080",
                "allowed_schemes": "http",
                "path_prefix": "/api",
            }]
        )

        controller = AutonomousController(
            evidence_store=temp_store,
            policy_service=policy_service,
        )

        # Attempt to target port 9999 (not authorized)
        result = controller.run_assessment(
            target_url="http://127.0.0.1:9999/api",
            policy_id=policy["id"],
        )

        assert result["success"] is False
        assert "Pre-assessment policy rejection" in result["error"]
        assert result["session_id"] is None

    def test_controller_rejects_unauthorized_category_before_session(self, policy_service, temp_store):
        """Assessment requesting unauthorized category is rejected before session creation."""
        cfg = get_default_policy_config()
        cfg["allowed_categories"] = ["RECONNAISSANCE"]  # Only recon allowed

        policy = policy_service.create_policy(
            name="Recon Only Policy",
            description="No active probing",
            config=cfg,
            creator_id=1,
            targets=[{
                "host_pattern": "127.0.0.1",
                "port_range": "8000",
                "allowed_schemes": "http",
                "path_prefix": "/",
            }]
        )

        controller = AutonomousController(
            evidence_store=temp_store,
            policy_service=policy_service,
        )

        # Request ACTIVE_PROBE category
        result = controller.run_assessment(
            target_url="http://127.0.0.1:8000/",
            policy_id=policy["id"],
            selected_categories=["ACTIVE_PROBE"],
        )

        assert result["success"] is False
        assert "Test categories not permitted by policy" in result["error"]
        assert result["session_id"] is None
