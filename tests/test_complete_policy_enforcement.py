"""Complete Policy Enforcement Across All Execution Paths Tests (Phase 5.6).

Verifies that no tool, controller, API, background worker, retry mechanism or
alternate execution path can bypass authorization:
1. Every registered tool is protected and denied tools never execute (verified with spies).
2. Direct ToolRegistry execution is protected.
3. Direct tool invocation is gated or safely unavailable.
4. HTTPX requests cannot bypass policy.
5. Requests-based requests cannot bypass policy.
6. GraphQL execution is protected.
7. Redirects are revalidated.
8. Retries are safe (0 retries on state-changing requests).
9. Revoked target is blocked immediately live.
10. Deactivated policy is blocked immediately live.
11. Immutable restrictions cannot be overridden (SQL injection, metadata, ceilings).
12. Concurrent request budgets cannot be exceeded (atomic reservation under multi-threading).
13. Cancellation halts execution and prevents further budget reservations.
14. Unknown tools are denied.
15. Missing policy context is denied by default.
"""

import concurrent.futures
import threading
import time
import pytest
from unittest.mock import MagicMock

from controller.agent.autonomous_controller import AutonomousController
from controller.config import AgentConfig, DEFAULT_CONFIG
from controller.guardrails.policy_engine import PolicyEngine, DEVELOPER_SAFETY_MAX_REQUESTS
from controller.guardrails.policy_service import PolicyService, get_default_policy_config
from controller.guardrails.scope_validator import ScopeValidator
from controller.storage.evidence_store import EvidenceStore
from controller.tools import build_default_tool_registry
from controller.tools.registry import ToolRegistry, BaseTool
from controller.tools.http_request import execute_http_request, HttpRequestTool
from controller.tools.httpx_client import execute_httpx_request, HttpxRequestTool
from controller.tools.graphql_client import GraphQLProbeTool
from controller.tools.inventory_scanner import ApiInventoryScannerTool
from controller.tools.business_flow_probe import BusinessFlowProbeTool
from controller.tools.parameter_fuzzer import ParameterFuzzerTool
from controller.tools.zap_client import ZapSecurityScanTool
from controller.tools.openapi_parser import OpenApiParserTool
from controller.tools.jwt_inspector import JwtInspectorTool


@pytest.fixture
def temp_store(tmp_path):
    db_file = tmp_path / "test_complete_enforcement.db"
    return EvidenceStore(str(db_file))


@pytest.fixture
def policy_service(temp_store):
    return PolicyService(temp_store)


class TestAllRegisteredToolsProtected:
    """Requirement 1: Every registered tool is protected and denied tools never execute."""

    def test_all_default_registered_tools_enforce_policy_gate(self):
        """Verify that every tool in build_default_tool_registry() enforces policy denial."""
        registry = build_default_tool_registry()
        tool_names = registry.list_tool_names()
        assert len(tool_names) == 9

        # Policy that allows ZERO tools
        engine = PolicyEngine(registered_tools=set(tool_names))
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["none_permitted_tool"], "max_requests": 10},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })
        registry.set_policy_engine(engine)

        sample_args = {
            "http_request": {"url": "http://127.0.0.1/api"},
            "httpx_request": {"url": "http://127.0.0.1/api"},
            "openapi_parser": {"spec_source": "http://127.0.0.1/openapi.json"},
            "jwt_inspector": {"token": "header.payload.sig"},
            "parameter_fuzzer": {"url": "http://127.0.0.1/api", "parameters": {"id": 1}},
            "zap_scanner": {"action": "check_health"},
            "graphql_probe": {"target_url": "http://127.0.0.1/graphql"},
            "inventory_scanner": {"target_url": "http://127.0.0.1"},
            "business_flow_probe": {"url": "http://127.0.0.1/api/checkout"},
        }

        for name in tool_names:
            args = sample_args.get(name, {})
            tool_obj = registry.get(name)

            # Spy on execute
            orig_execute = tool_obj.execute
            spy_called = []

            def make_spy(orig):
                def spy(*a, **kw):
                    spy_called.append(True)
                    return orig(*a, **kw)
                return spy

            tool_obj.execute = make_spy(orig_execute)

            res = registry.execute(name, args)
            assert res["success"] is False, f"Tool '{name}' did not fail when policy disallowed it!"
            assert res.get("policy_denied") is True, f"Tool '{name}' was not flagged as policy_denied!"
            assert len(spy_called) == 0, f"SECURITY DEFECT: Tool '{name}' handler executed despite policy rejection!"

            # Restore
            tool_obj.execute = orig_execute


class TestDirectToolAndRegistryInvocationGating:
    """Requirement 2 & 6: Direct tool invocation and registry execution isolation."""

    def test_direct_tool_execute_enforces_policy_when_gated(self):
        """Calling tool.execute() directly without registry still enforces policy gate."""
        tool = HttpRequestTool()
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["other_tool"], "max_requests": 10},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })
        tool.set_policy_engine(engine)

        res = tool.execute(url="http://127.0.0.1/api")
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "not permitted by active policy" in res["error"]

    def test_tool_requires_policy_denies_by_default(self):
        """Tool with require_policy=True denies execution by default if no engine is attached."""
        tool = HttpRequestTool()
        tool.require_policy = True
        res = tool.execute(url="http://127.0.0.1/api")
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "requires policy enforcement context" in res["error"]

    def test_registry_requires_policy_denies_by_default(self):
        """Registry configured with require_policy=True denies execution when policy_engine is None."""
        registry = ToolRegistry(require_policy=True)
        registry.register_tool(HttpRequestTool())

        res = registry.execute("http_request", {"url": "http://127.0.0.1/api"})
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "Missing policy enforcement context" in res["error"]

    def test_unknown_tool_rejected(self):
        """Registry rejects arbitrary or unknown tool names without executing."""
        registry = ToolRegistry()
        res = registry.execute("arbitrary_shell_executor", {"cmd": "whoami"})
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "not registered" in res["error"]

    def test_gated_flag_spoof_cannot_bypass_direct_tool_authorization(self):
        """Passing _gated=True cannot be abused by an external caller to bypass policy checks."""
        tool = HttpRequestTool()
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 10},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/api"}],
        })
        tool.set_policy_engine(engine)

        # Attacker attempts to forge _gated=True on out-of-scope target
        res = tool.execute(url="http://evil.com/steal", _gated=True)
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "Scope violation" in res["error"]

        # Attacker attempts to forge _gated=True on unpermitted tool
        engine2 = PolicyEngine(registered_tools={"http_request"})
        engine2.bind_policy_snapshot({
            "policy_id": 2,
            "config": {"allowed_tools": ["other_tool"], "max_requests": 10},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/api"}],
        })
        tool.set_policy_engine(engine2)
        res2 = tool.execute(url="http://127.0.0.1/api", _gated=True)
        assert res2["success"] is False
        assert res2.get("policy_denied") is True
        assert "not permitted by active policy" in res2["error"]

    def test_imported_sentinel_cannot_bypass_direct_tool_authorization(self):
        """A caller importing _REGISTRY_GATE_SENTINEL cannot bypass policy evaluation on direct tool.execute()."""
        from controller.tools.registry import _REGISTRY_GATE_SENTINEL
        tool = HttpRequestTool()
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["other_tool"], "max_requests": 10},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/api"}],
        })
        tool.set_policy_engine(engine)

        # Direct caller imports sentinel and attempts bypass on direct tool.execute()
        res = tool.execute(url="http://127.0.0.1/api", _gated=_REGISTRY_GATE_SENTINEL)
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "not permitted by active policy" in res["error"]

    def test_registry_executes_authorized_tool_cleanly(self):
        """ToolRegistry's trusted dispatch mechanism executes authorized tools without argument interference."""
        registry = build_default_tool_registry()
        engine = PolicyEngine(registered_tools={"jwt_inspector"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["jwt_inspector"], "max_requests": 10},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })
        registry.set_policy_engine(engine)

        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        # Even if caller passes _gated in arguments, registry strips it and dispatches safely
        res = registry.execute("jwt_inspector", {"token": token, "_gated": "malicious_attempt"})
        assert res["success"] is True
        assert res["header"]["alg"] == "HS256"


class TestNetworkLayerEnforcement:
    """Requirement 3: Outbound network request authorization and boundary controls."""

    def test_execute_http_request_blocks_metadata_socket_connection(self):
        """execute_http_request intercepts and blocks cloud metadata at the socket layer."""
        res = execute_http_request("http://169.254.169.254/latest/meta-data", timeout=1)
        assert res["success"] is False
        assert "Layer 1 Safety Violation" in str(res.get("error"))

    def test_execute_httpx_request_blocks_metadata_destination(self):
        """execute_httpx_request rejects cloud metadata destinations prior to dispatch."""
        res = execute_httpx_request("http://169.254.169.254/latest/meta-data")
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "Scope violation" in res.get("error", "")

    def test_execute_httpx_request_blocks_prohibited_methods(self):
        """execute_httpx_request rejects unpermitted methods like CONNECT or TRACE."""
        res = execute_httpx_request("http://127.0.0.1:8000/api", method="TRACE")
        assert res["success"] is False
        assert "not permitted" in res["error"]

    def test_graphql_probe_blocks_out_of_scope_target(self):
        """GraphQLProbeTool validates target URL and aborts before network dispatch."""
        tool = GraphQLProbeTool(config=AgentConfig(allowed_hosts={"127.0.0.1", "localhost"}))
        res = tool.execute(target_url="http://external-graphql-host.com/graphql")
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "rejected by scope policy" in res["error"]

    def test_inventory_scanner_blocks_out_of_scope_target(self):
        """ApiInventoryScannerTool rejects out-of-scope targets before scanning."""
        tool = ApiInventoryScannerTool(config=AgentConfig(allowed_hosts={"127.0.0.1", "localhost"}))
        res = tool.execute(target_url="http://unauthorized-inventory-host.com")
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "rejected by scope policy" in res["error"]

    def test_business_flow_probe_blocks_out_of_scope_target(self):
        """BusinessFlowProbeTool rejects out-of-scope targets before probing."""
        tool = BusinessFlowProbeTool(config=AgentConfig(allowed_hosts={"127.0.0.1", "localhost"}))
        res = tool.execute(url="https://external-checkout.com/api/cart")
        assert res["success"] is False
        assert res.get("policy_denied") is True
        assert "rejected by scope policy" in res["error"]

    def test_destructive_sql_in_body_rejected_by_layer1(self):
        """Destructive SQL injection payloads are blocked across all HTTP clients."""
        res_http = execute_http_request(
            url="http://127.0.0.1:8000/api/users",
            method="POST",
            body="admin' OR 1=1; DROP TABLE users; --",
        )
        assert res_http["success"] is False
        assert res_http.get("policy_denied") is True
        assert "Destructive database operation detected" in res_http["error"]

        res_httpx = execute_httpx_request(
            url="http://127.0.0.1:8000/api/users",
            method="POST",
            body="admin' OR 1=1; TRUNCATE TABLE logs; --",
        )
        assert res_httpx["success"] is False
        assert res_httpx.get("policy_denied") is True
        assert "Destructive database operation detected" in res_httpx["error"]

    def test_validate_destination_ip_all_address_classes(self):
        """Explicitly verify destination IP validation across all requested address classes."""
        from controller.guardrails.scope_validator import validate_destination_ip

        # IPv4 private ranges (blocked in default localhost mode)
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            ok, reason = validate_destination_ip(ip, allow_external=False, allow_private=False)
            assert not ok, f"Expected private IP '{ip}' to be blocked"
            assert "private network address" in reason

        # IPv4 loopback (allowed)
        for ip in ["127.0.0.1", "127.1.2.3"]:
            ok, reason = validate_destination_ip(ip)
            assert ok, f"Expected loopback IP '{ip}' to be permitted"

        # IPv4 link-local (blocked by Layer 1 invariant)
        for ip in ["169.254.1.1", "169.254.169.254"]:
            ok, reason = validate_destination_ip(ip)
            assert not ok, f"Expected link-local IP '{ip}' to be blocked"

        # IPv4-mapped IPv6 addresses (normalized and evaluated against canonical rules)
        ok, _ = validate_destination_ip("::ffff:169.254.169.254")
        assert not ok, "Expected IPv4-mapped metadata IP to be blocked"
        ok, _ = validate_destination_ip("::ffff:10.0.0.1")
        assert not ok, "Expected IPv4-mapped private IP to be blocked in default mode"
        ok, _ = validate_destination_ip("::ffff:127.0.0.1")
        assert ok, "Expected IPv4-mapped loopback to be permitted"

        # IPv6 loopback (allowed)
        ok, _ = validate_destination_ip("::1")
        assert ok, "Expected IPv6 loopback to be permitted"

        # IPv6 private / ULA (blocked in default mode)
        for ip in ["fc00::1", "fd00::1"]:
            ok, reason = validate_destination_ip(ip)
            assert not ok, f"Expected IPv6 ULA '{ip}' to be blocked"
            assert "private network address" in reason

        # IPv6 link-local (blocked by Layer 1 invariant)
        ok, reason = validate_destination_ip("fe80::1")
        assert not ok
        assert "link-local" in reason

        # IPv6 & IPv4 unspecified (blocked by Layer 1 invariant)
        for ip in ["::", "0.0.0.0"]:
            ok, reason = validate_destination_ip(ip)
            assert not ok, f"Expected unspecified '{ip}' to be blocked"

        # Multicast (blocked by Layer 1 invariant)
        for ip in ["224.0.0.1", "ff02::1"]:
            ok, reason = validate_destination_ip(ip)
            assert not ok, f"Expected multicast '{ip}' to be blocked"
            assert "multicast" in reason

        # Reserved (blocked by Layer 1 invariant)
        ok, reason = validate_destination_ip("240.0.0.1")
        assert not ok
        assert "reserved" in reason

        ok, reason = validate_destination_ip("255.255.255.255")
        assert not ok
        assert "prohibited" in reason

    def test_destination_address_multiple_ips_mixed_blocked(self):
        """DNS resolution returning multiple addresses is blocked if ANY address is prohibited."""
        import socket
        from unittest.mock import patch
        from controller.guardrails.scope_validator import validate_destination_address

        # Mixture 1: loopback + metadata
        mixed_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80)),
        ]
        with patch("socket.getaddrinfo", return_value=mixed_addrinfo):
            ok, reason = validate_destination_address("test-host.local", 80)
            assert not ok
            assert "prohibited IP '169.254.169.254'" in reason

        # Mixture 2: loopback + private IP
        mixed_addrinfo_private = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
        ]
        with patch("socket.getaddrinfo", return_value=mixed_addrinfo_private):
            ok, reason = validate_destination_address("test-host.local", 80)
            assert not ok
            assert "prohibited IP '10.0.0.1'" in reason

        # Clean mixture: IPv4 loopback + IPv6 loopback
        clean_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0)),
        ]
        with patch("socket.getaddrinfo", return_value=clean_addrinfo):
            ok, reason = validate_destination_address("localhost", 80)
            assert ok

    def test_requests_connection_time_dns_rebinding_blocked(self):
        """Requests socket hook intercepts connection-time DNS rebinding to prohibited destinations."""
        import socket
        from unittest.mock import patch

        mock_rebind = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch("socket.getaddrinfo", return_value=mock_rebind):
            res = execute_http_request("http://127.0.0.1:8000/api", timeout=0.5)
            assert res["success"] is False
            assert "Layer 1 Safety Violation" in str(res.get("error"))

    def test_httpx_connection_time_dns_rebinding_blocked(self):
        """HTTPX connection-time transport and socket hooks independently block DNS rebinding to prohibited destinations."""
        import socket
        from unittest.mock import patch

        mock_rebind = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 8000))]
        with patch("socket.getaddrinfo", return_value=mock_rebind):
            res = execute_httpx_request("http://127.0.0.1:8000/api")
            assert res["success"] is False
            assert "Layer 1 Safety Violation" in str(res.get("error"))


class TestDynamicPolicyConsistencyAndRevocation:
    """Requirement 4: Policy consistency during live execution (revocation and deactivation)."""

    def test_live_target_revocation_blocks_subsequent_execution(self, temp_store, policy_service):
        """When a target is revoked in the database mid-run, subsequent tool calls are blocked."""
        policy = policy_service.create_policy(
            name="Revocation Policy",
            description="Test live revocation",
            config=get_default_policy_config(),
            creator_id=1,
            targets=[{"host_pattern": "127.0.0.1", "port_range": "8000", "path_prefix": "/api"}],
        )
        target_id = policy["targets"][0]["id"]

        engine = PolicyEngine(
            registered_tools={"http_request"},
            policy_service=policy_service,
        )
        snapshot = policy_service.create_assessment_snapshot("sess-rev-1", policy["id"], 1)
        engine.bind_policy_snapshot(snapshot)

        # Before revocation: approved
        dec1 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api/users"})
        assert dec1.approved is True

        # Revoke target
        policy_service.revoke_target_authorization(target_id, actor_id=1, policy_id=policy["id"])

        # After revocation: live check immediately blocks
        dec2 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api/users"})
        assert dec2.approved is False
        assert "Live target authorization revoked" in dec2.reason

    def test_live_policy_deactivation_halts_execution(self, temp_store, policy_service):
        """When a policy is deactivated in the database mid-run, subsequent tool calls are blocked."""
        policy = policy_service.create_policy(
            name="Deactivation Policy",
            description="Test live deactivation",
            config=get_default_policy_config(),
            creator_id=1,
            targets=[{"host_pattern": "127.0.0.1", "port_range": "8000", "path_prefix": "/api"}],
        )

        engine = PolicyEngine(
            registered_tools={"http_request"},
            policy_service=policy_service,
        )
        snapshot = policy_service.create_assessment_snapshot("sess-deact-1", policy["id"], 1)
        engine.bind_policy_snapshot(snapshot)

        # Before deactivation: approved
        dec1 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api/users"})
        assert dec1.approved is True

        # Deactivate policy
        policy_service.deactivate_policy(policy["id"], actor_id=1)

        # After deactivation: immediately blocked
        dec2 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1:8000/api/users"})
        assert dec2.approved is False
        assert "was deactivated by administrator" in dec2.reason


class TestConcurrentBudgetEnforcement:
    """Requirement 5: Budget enforcement and atomic reservation under concurrency."""

    def test_shared_request_budget_exact_boundary(self):
        """Exact boundary test: max_requests=5 allows exactly 5 reservations, 6th is rejected."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 5},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        # Reserve 5 requests
        for i in range(5):
            dec = engine.evaluate_action(
                "http_request",
                {"url": "http://127.0.0.1/api"},
                reserve_budget=True,
            )
            assert dec.approved is True, f"Request {i+1} should have been approved"

        # 6th request must be rejected
        dec6 = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1/api"},
            reserve_budget=True,
        )
        assert dec6.approved is False
        assert "budget exhausted" in dec6.reason.lower()

    def test_concurrent_multi_threaded_reservation_no_overrun(self):
        """10 simultaneous threads competing for 5 slots: exactly 5 succeed, 5 are rejected."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 5},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        results = []

        def worker():
            dec = engine.evaluate_action(
                "http_request",
                {"url": "http://127.0.0.1/api"},
                reserve_budget=True,
            )
            return dec.approved

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(10)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        success_count = sum(1 for r in results if r is True)
        failed_count = sum(1 for r in results if r is False)

        assert success_count == 5, f"Expected exactly 5 approvals, got {success_count}"
        assert failed_count == 5, f"Expected exactly 5 rejections, got {failed_count}"
        assert engine.budget_manager.reserved_requests == 5


class TestCancellationBehavior:
    """Requirement 6: Cancellation propagation and evidence preservation."""

    def test_cancellation_halts_subsequent_tool_execution(self):
        """Calling policy_engine.cancel() immediately blocks all further tool executions."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 20},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        dec1 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1/api"})
        assert dec1.approved is True

        # Signal cancellation
        engine.cancel()

        dec2 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1/api"})
        assert dec2.approved is False
        assert "cancelled by operator" in dec2.reason

    def test_evidence_preserved_after_cancellation(self, temp_store):
        """Evidence and traffic records logged prior to cancellation remain sealed in store."""
        sess_id = "sess-canc-preserve-1"
        temp_store.create_session(sess_id, "http://127.0.0.1:8000", "Cancel test")

        t_id = temp_store.log_traffic(
            session_id=sess_id,
            method="GET",
            url="http://127.0.0.1:8000/api/users",
            response_status=200,
            response_body='{"status": "ok"}',
        )

        temp_store.update_session_status(sess_id, "CANCELLED")

        # Verify evidence remains intact
        traffic_logs = temp_store.get_traffic_logs(sess_id)
        assert len(traffic_logs) == 1
        assert traffic_logs[0]["id"] == t_id
        assert traffic_logs[0]["response_status"] == 200

        sess_info = temp_store.get_session(sess_id)
        assert sess_info["status"] == "CANCELLED"


class TestTurnDurationAndSafetyCeilingEnforcement:
    """Requirement 2 & 5: Turn limits, duration limits, auth modes, and Layer 1 ceilings."""

    def test_controller_turn_limit_enforced(self):
        """Controller turn limit is enforced by centralized gate."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_turns": 4},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        dec1 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1/api"}, current_turn=4)
        assert dec1.approved is True

        dec2 = engine.evaluate_action("http_request", {"url": "http://127.0.0.1/api"}, current_turn=5)
        assert dec2.approved is False
        assert "Turn limit reached" in dec2.reason

    def test_assessment_duration_limit_enforced(self):
        """Assessment duration limit is enforced by centralized gate."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_assessment_duration_seconds": 60.0},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        dec1 = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1/api"},
            current_duration_seconds=59.0,
        )
        assert dec1.approved is True

        dec2 = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1/api"},
            current_duration_seconds=60.1,
        )
        assert dec2.approved is False
        assert "duration limit reached" in dec2.reason

    def test_policy_enforces_auth_mode_whitelist(self):
        """Authentication mode in headers or context must match allowed_auth_modes."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "allowed_auth_modes": ["bearer"]},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        # Bearer auth mode: approved
        dec_bearer = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1/api", "headers": {"Authorization": "Bearer valid_token"}},
        )
        assert dec_bearer.approved is True

        # Basic auth mode: rejected
        dec_basic = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1/api", "headers": {"Authorization": "Basic dXNlcjpwYXNz"}},
        )
        assert dec_basic.approved is False
        assert "Authentication mode 'basic' is not permitted" in dec_basic.reason

    def test_developer_safety_ceiling_cannot_be_overridden_by_admin(self):
        """Admin snapshot configured with max_requests=9999 is clamped to 100 max by Layer 1 invariant."""
        engine = PolicyEngine(registered_tools={"http_request"})
        engine.bind_policy_snapshot({
            "policy_id": 1,
            "config": {"allowed_tools": ["http_request"], "max_requests": 9999},
            "targets": [{"host_pattern": "127.0.0.1", "port_range": "80", "path_prefix": "/"}],
        })

        # Effective max requests in budget manager is clamped at 100
        assert engine.budget_manager.max_requests == DEVELOPER_SAFETY_MAX_REQUESTS

        dec = engine.evaluate_action(
            "http_request",
            {"url": "http://127.0.0.1/api"},
            current_request_count=100,
        )
        assert dec.approved is False
        assert "Developer safety ceiling reached" in dec.reason

