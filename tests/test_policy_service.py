"""Tests for PolicyService and Policy Versioning.

Validates policy CRUD, strict schema validation, immutable version history,
rollback functionality, target authorizations, assessment policy snapshots,
and audit log integration.
"""

import os
import tempfile
import pytest

from controller.storage.evidence_store import EvidenceStore
from controller.guardrails.policy_service import (
    PolicyService,
    DEVELOPER_SAFETY_MAX_REQUESTS,
    get_default_policy_config,
)


@pytest.fixture
def temp_store(tmp_path):
    db_file = tmp_path / "test_policy.db"
    return EvidenceStore(str(db_file))


@pytest.fixture
def policy_service(temp_store):
    return PolicyService(temp_store)


class TestPolicyService:
    """Test suite for PolicyService core capabilities."""

    def test_policy_creation_and_version_1(self, policy_service):
        """Creating a policy must persist the policy and initialize Version 1."""
        config = get_default_policy_config()
        config["max_requests"] = 20

        policy = policy_service.create_policy(
            name="Standard Testing Policy",
            description="Policy for standard API testing",
            config=config,
            creator_id=1,
            targets=[{
                "host_pattern": "127.0.0.1",
                "port_range": "8000-8080",
                "allowed_schemes": "http,https",
                "path_prefix": "/api",
            }]
        )

        assert policy is not None
        assert policy["name"] == "Standard Testing Policy"
        assert policy["current_version"] == 1
        assert policy["is_active"] is True
        assert policy["config"]["max_requests"] == 20
        assert len(policy["targets"]) == 1
        assert policy["targets"][0]["host_pattern"] == "127.0.0.1"

        # Verify Version 1 record in policy_versions
        v1 = policy_service.get_policy_version(policy["id"], 1)
        assert v1 is not None
        assert v1["version"] == 1
        assert v1["config"]["max_requests"] == 20
        assert v1["created_by"] == 1

    def test_strict_policy_validation_rejects_unknown_keys(self, policy_service):
        """Configuration dictionary with unknown keys must be strictly rejected."""
        invalid_config = get_default_policy_config()
        invalid_config["unrecognized_custom_key"] = "dangerous_value"

        with pytest.raises(ValueError, match="Unrecognized policy configuration keys"):
            policy_service.create_policy(
                name="Invalid Policy",
                description="Test",
                config=invalid_config,
                creator_id=1,
            )

    def test_strict_policy_validation_rejects_unknown_tools(self, policy_service):
        """Configuration containing unauthorized tool names must be rejected."""
        invalid_config = get_default_policy_config()
        invalid_config["allowed_tools"] = ["http_request", "malicious_unregistered_tool"]

        with pytest.raises(ValueError, match="Unknown tools in allowed_tools"):
            policy_service.create_policy(
                name="Invalid Tools Policy",
                description="Test",
                config=invalid_config,
                creator_id=1,
            )

    def test_strict_policy_validation_rejects_unsupported_methods(self, policy_service):
        """Unsupported HTTP methods must be rejected."""
        invalid_config = get_default_policy_config()
        invalid_config["allowed_http_methods"] = ["GET", "TRACE", "CONNECT"]

        with pytest.raises(ValueError, match="Unsupported HTTP methods"):
            policy_service.create_policy(
                name="Invalid Methods Policy",
                description="Test",
                config=invalid_config,
                creator_id=1,
            )

    def test_strict_policy_validation_rejects_out_of_bound_limits(self, policy_service):
        """Resource limits exceeding safety ceilings or negative values must be rejected."""
        invalid_config = get_default_policy_config()
        invalid_config["max_requests"] = 250  # Exceeds DEVELOPER_SAFETY_MAX_REQUESTS (100)

        with pytest.raises(ValueError, match="max_requests"):
            policy_service.create_policy(
                name="Exceeded Requests Policy",
                description="Test",
                config=invalid_config,
                creator_id=1,
            )

        invalid_config2 = get_default_policy_config()
        invalid_config2["max_turns"] = -5
        with pytest.raises(ValueError, match="max_turns"):
            policy_service.create_policy(
                name="Negative Turns Policy",
                description="Test",
                config=invalid_config2,
                creator_id=1,
            )

    def test_immutable_version_update_and_history(self, policy_service):
        """Updating a policy creates a new version row and preserves previous versions untouched."""
        config_v1 = get_default_policy_config()
        config_v1["max_requests"] = 15

        policy = policy_service.create_policy(
            name="Versioned Policy",
            description="Version 1",
            config=config_v1,
            creator_id=1,
        )
        policy_id = policy["id"]

        # Update to Version 2
        config_v2 = get_default_policy_config()
        config_v2["max_requests"] = 30
        updated = policy_service.update_policy(
            policy_id=policy_id,
            new_config=config_v2,
            modifier_id=2,
            change_summary="Increased max_requests to 30",
        )

        assert updated["current_version"] == 2
        assert updated["config"]["max_requests"] == 30

        # Verify historical versions list
        versions = policy_service.list_policy_versions(policy_id)
        assert len(versions) == 2
        assert versions[0]["version"] == 1
        assert versions[0]["config"]["max_requests"] == 15
        assert versions[1]["version"] == 2
        assert versions[1]["config"]["max_requests"] == 30

    def test_policy_rollback_creates_new_version_with_previous_config(self, policy_service):
        """Rollback restores an earlier configuration as an explicit new version."""
        config_v1 = get_default_policy_config()
        config_v1["max_requests"] = 10

        policy = policy_service.create_policy(
            name="Rollback Policy",
            description="Base",
            config=config_v1,
            creator_id=1,
        )
        policy_id = policy["id"]

        # Bump to Version 2
        config_v2 = get_default_policy_config()
        config_v2["max_requests"] = 40
        policy_service.update_policy(policy_id, config_v2, modifier_id=1)

        # Rollback to Version 1 -> Creates Version 3 with Version 1 configuration
        rolled_back = policy_service.rollback_policy_version(policy_id, target_version=1, modifier_id=3)
        assert rolled_back["current_version"] == 3
        assert rolled_back["config"]["max_requests"] == 10

        versions = policy_service.list_policy_versions(policy_id)
        assert len(versions) == 3
        assert versions[2]["version"] == 3
        assert "Rollback to configuration from Version 1" in versions[2]["change_summary"]

    def test_policy_activation_and_deactivation(self, policy_service):
        """Policy active state toggling."""
        policy = policy_service.create_policy(
            name="Toggle Policy",
            description="Test",
            config=get_default_policy_config(),
            creator_id=1,
        )
        policy_id = policy["id"]
        assert policy["is_active"] is True

        assert policy_service.deactivate_policy(policy_id, actor_id=1) is True
        pol_deact = policy_service.get_policy(policy_id)
        assert pol_deact["is_active"] is False

        assert policy_service.activate_policy(policy_id, actor_id=1) is True
        pol_act = policy_service.get_policy(policy_id)
        assert pol_act["is_active"] is True

    def test_audit_log_entries_recorded_for_all_mutations(self, policy_service, temp_store):
        """All policy mutations must create corresponding records in admin_audit_log."""
        policy = policy_service.create_policy(
            name="Audited Policy",
            description="Test audit",
            config=get_default_policy_config(),
            creator_id=1,
        )
        policy_id = policy["id"]

        policy_service.update_policy(
            policy_id=policy_id,
            new_config=get_default_policy_config(),
            modifier_id=1,
            change_summary="Update for audit",
        )
        policy_service.deactivate_policy(policy_id, actor_id=1)

        with temp_store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT action, resource_type, resource_id FROM admin_audit_log ORDER BY id ASC")
            logs = cursor.fetchall()

        actions = [r["action"] for r in logs]
        assert "POLICY_CREATED" in actions
        assert "POLICY_UPDATED" in actions
        assert "POLICY_DEACTIVATED" in actions

    def test_assessment_snapshot_freezes_exact_policy_state(self, policy_service):
        """Assessment policy snapshot freezes exact configuration and targets for audit immutability."""
        policy = policy_service.create_policy(
            name="Snapshot Base Policy",
            description="Testing snapshots",
            config=get_default_policy_config(),
            creator_id=1,
            targets=[{
                "host_pattern": "127.0.0.1",
                "port_range": "8080",
                "allowed_schemes": "http",
                "path_prefix": "/api/v1",
            }]
        )

        session_id = "test-session-snapshot-001"
        snapshot = policy_service.create_assessment_snapshot(
            session_id=session_id,
            policy_id=policy["id"],
            applied_by_user_id=1,
        )

        assert snapshot is not None
        assert snapshot["assessment_session_id"] == session_id
        assert snapshot["policy_id"] == policy["id"]
        assert snapshot["policy_version"] == 1
        assert len(snapshot["targets"]) == 1

        # Now update the base policy to Version 2
        config_v2 = get_default_policy_config()
        config_v2["max_requests"] = 5
        policy_service.update_policy(
            policy_id=policy["id"],
            new_config=config_v2,
            modifier_id=1,
            new_targets=[{
                "host_pattern": "localhost",
                "port_range": "3000",
                "allowed_schemes": "http",
                "path_prefix": "/v2",
            }]
        )

        # Retrieve the assessment snapshot again: must remain on Version 1 config and targets
        stored_snapshot = policy_service.get_assessment_snapshot(session_id)
        assert stored_snapshot["policy_version"] == 1
        assert stored_snapshot["targets"][0]["port_range"] == "8080"
        assert stored_snapshot["config"]["max_requests"] == 25  # original default
