"""Phase 7.0: Security Boundary Verification Suite.

Systematically verifies the 10 core security boundaries of the platform:
1. Target Scope Rejection (unauthorized host/port blocked by policy)
2. Layer 1 Socket SSRF Interception (pre-connect check blocks unauthorized IP)
3. Private IP Blocking (prohibits internal network pivoting)
4. Request Budget Enforcement (hard cutoff stops requests immediately)
5. Turn Limit Enforcement (halts assessment when max turns reached)
6. Target Policy Revocation (revoking authorization halts subsequent execution)
7. Sentinel Forgery & Direct Invocation Protection (unforgeable gate sentinel)
8. First-run Credential and Password Change Security (must_change_password gating)
9. Cryptographic Evidence Integrity (tampered records flagged by hash verification)
10. Unregistered Tool Invocation Blocking (unauthorized tools rejected by policy)
"""

import json
import os
import shutil
import socket
import sqlite3
import sys
import time
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller.agent.autonomous_controller import AutonomousController
from controller.auth.authentication_service import AuthenticationService
from controller.config import AgentConfig
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.policy_service import PolicyService
from controller.guardrails.scope_validator import (
    ScopeValidator,
    validate_destination_address,
    validate_destination_ip,
)
from controller.storage.evidence_store import EvidenceStore
from controller.tools import build_default_tool_registry
from controller.tools.http_request import HttpRequestTool, execute_http_request
from controller.tools.registry import _REGISTRY_GATE_SENTINEL


def run_security_boundary_tests() -> dict:
    results = []
    print("=" * 78)
    print("   PHASE 7.0: SECURITY BOUNDARY VERIFICATION")
    print("=" * 78)

    db_path = PROJECT_ROOT / "research" / "phase7" / "phase7_sec_test.db"
    if db_path.exists():
        db_path.unlink()

    store = EvidenceStore(str(db_path))
    auth_svc = AuthenticationService(store=store)
    policy_svc = PolicyService(store=store)

    # -------------------------------------------------------------
    # 1. Target Scope Rejection
    # -------------------------------------------------------------
    try:
        config = AgentConfig(allowed_hosts={"127.0.0.1", "localhost"})
        policy = PolicyEngine(config=config, registered_tools={"http_request"})
        dec = policy.evaluate_action("http_request", {"url": "http://unauthorized-internal.corp/secret"})
        assert not dec.approved, "Unauthorized host was approved!"
        assert "Scope violation" in dec.reason or "not authorized" in dec.reason
        results.append({
            "boundary_id": "SEC-01",
            "name": "Target Scope Rejection",
            "passed": True,
            "details": f"Deterministically blocked: {dec.reason}",
        })
        print(" [PASS] SEC-01: Target Scope Rejection")
    except Exception as e:
        results.append({"boundary_id": "SEC-01", "name": "Target Scope Rejection", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-01: {e}")

    # -------------------------------------------------------------
    # 2. Layer 1 Socket SSRF Interception (Pre-connect validation)
    # -------------------------------------------------------------
    try:
        res = execute_http_request("http://169.254.169.254/latest/meta-data", timeout=1)
        assert res["success"] is False, "Metadata endpoint request succeeded!"
        assert "Layer 1 Safety Violation" in str(res.get("error"))

        # DNS rebinding check
        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            res_rebind = execute_http_request("http://rebind-test.local/probe", timeout=1)
            assert res_rebind["success"] is False
            assert "Layer 1 Safety Violation" in str(res_rebind.get("error"))

        results.append({
            "boundary_id": "SEC-02",
            "name": "Layer 1 Socket SSRF Interception",
            "passed": True,
            "details": "Direct socket connect to 169.254.169.254 and DNS-rebound answers blocked before socket connection",
        })
        print(" [PASS] SEC-02: Layer 1 Socket SSRF Interception")
    except Exception as e:
        results.append({"boundary_id": "SEC-02", "name": "Layer 1 Socket SSRF Interception", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-02: {e}")

    # -------------------------------------------------------------
    # 3. Private IP Range Interception
    # -------------------------------------------------------------
    try:
        private_ips = ["10.254.1.1", "172.16.5.4", "192.168.1.1", "169.254.169.254"]
        all_blocked = True
        for pip in private_ips:
            valid, reason = validate_destination_ip(pip)
            if valid:
                all_blocked = False
                break
        assert all_blocked, f"Private IP {pip} was not blocked by validate_destination_ip!"
        results.append({
            "boundary_id": "SEC-03",
            "name": "Private IP Range Interception",
            "passed": True,
            "details": f"All tested private/link-local/cloud-metadata IPs blocked ({', '.join(private_ips)})",
        })
        print(" [PASS] SEC-03: Private IP Range Interception")
    except Exception as e:
        results.append({"boundary_id": "SEC-03", "name": "Private IP Range Interception", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-03: {e}")

    # -------------------------------------------------------------
    # 4. Request Budget Enforcement
    # -------------------------------------------------------------
    try:
        budget_pol = policy_svc.create_policy(
            name="Budget Policy",
            config={"max_requests": 2, "max_turns": 10, "allowed_tools": ["http_request"]},
            creator_id=1,
            targets=[{"host_pattern": "127.0.0.1", "port_range": "8080", "path_prefix": "/"}],
        )
        pe = PolicyEngine(policy_service=policy_svc, policy_snapshot=budget_pol, registered_tools={"http_request"})
        # 1st request
        d1 = pe.evaluate_action("http_request", {"url": "http://127.0.0.1:8080/a"}, reserve_budget=True)
        assert d1.approved
        pe.record_completed_request()
        # 2nd request
        d2 = pe.evaluate_action("http_request", {"url": "http://127.0.0.1:8080/b"}, reserve_budget=True)
        assert d2.approved
        pe.record_completed_request()
        # 3rd request - should be hard blocked
        d3 = pe.evaluate_action("http_request", {"url": "http://127.0.0.1:8080/c"}, reserve_budget=True)
        assert not d3.approved, "Exceeded budget was approved!"
        assert "limit" in d3.reason.lower() or "budget" in d3.reason.lower()
        results.append({
            "boundary_id": "SEC-04",
            "name": "Request Budget Enforcement",
            "passed": True,
            "details": f"3rd request blocked at limit 2: {d3.reason}",
        })
        print(" [PASS] SEC-04: Request Budget Enforcement")
    except Exception as e:
        results.append({"boundary_id": "SEC-04", "name": "Request Budget Enforcement", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-04: {e}")

    # -------------------------------------------------------------
    # 5. Turn Limit Enforcement
    # -------------------------------------------------------------
    try:
        pe_turn = PolicyEngine(
            policy_service=policy_svc,
            policy_snapshot={
                "id": 999,
                "config": {"max_turns": 1, "max_requests": 100, "allowed_tools": ["http_request"]},
                "targets": [{"host_pattern": "127.0.0.1", "port_range": "8080", "path_prefix": "/"}],
            },
            registered_tools={"http_request"},
        )
        # Turn 1
        t1 = pe_turn.evaluate_action("http_request", {"url": "http://127.0.0.1:8080/step1"}, current_turn=1)
        assert t1.approved
        # Turn 2
        t2 = pe_turn.evaluate_action("http_request", {"url": "http://127.0.0.1:8080/step2"}, current_turn=2)
        assert not t2.approved, "Turn exceeded but approved!"
        assert "Turn limit reached" in t2.reason
        results.append({
            "boundary_id": "SEC-05",
            "name": "Turn Limit Enforcement",
            "passed": True,
            "details": f"Turn 2 blocked under max_turns=1: {t2.reason}",
        })
        print(" [PASS] SEC-05: Turn Limit Enforcement")
    except Exception as e:
        results.append({"boundary_id": "SEC-05", "name": "Turn Limit Enforcement", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-05: {e}")

    # -------------------------------------------------------------
    # 6. Target Policy Revocation
    # -------------------------------------------------------------
    try:
        rev_pol = policy_svc.create_policy(
            name="Revocation Policy",
            config={"max_requests": 50, "max_turns": 50, "allowed_tools": ["http_request"]},
            creator_id=1,
            targets=[{"host_pattern": "127.0.0.1", "port_range": "9099", "path_prefix": "/"}],
        )
        target_id = rev_pol["targets"][0]["id"]
        snapshot = policy_svc.create_assessment_snapshot("sess-rev-phase7", rev_pol["id"], 1)
        pe_rev = PolicyEngine(policy_service=policy_svc, registered_tools={"http_request"})
        pe_rev.bind_policy_snapshot(snapshot)

        # Before revocation: approved
        chk1 = pe_rev.evaluate_action("http_request", {"url": "http://127.0.0.1:9099/status"})
        assert chk1.approved, f"Initial check should be approved, got: {chk1.reason}"

        # Revoke target rule in service
        policy_svc.revoke_target_authorization(target_id, actor_id=1, policy_id=rev_pol["id"])

        # After revocation: live check immediately blocks
        chk2 = pe_rev.evaluate_action("http_request", {"url": "http://127.0.0.1:9099/status"})
        assert not chk2.approved, "Revoked target was still approved!"
        assert "Live target authorization revoked" in chk2.reason
        results.append({
            "boundary_id": "SEC-06",
            "name": "Live Target Revocation",
            "passed": True,
            "details": f"Action blocked immediately upon target revocation: {chk2.reason}",
        })
        print(" [PASS] SEC-06: Live Target Revocation")
    except Exception as e:
        results.append({"boundary_id": "SEC-06", "name": "Live Target Revocation", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-06: {e}")

    # -------------------------------------------------------------
    # 7. Sentinel Forgery & Direct Invocation Protection
    # -------------------------------------------------------------
    try:
        tool = HttpRequestTool()
        tool.set_policy_engine(None, require_policy=True)
        # Caller imports module sentinel and attempts bypass
        res = tool.execute(url="http://127.0.0.1:8080/test", _gated=_REGISTRY_GATE_SENTINEL)
        assert res.get("policy_denied") is True, f"Policy gating bypassed: {res}"
        results.append({
            "boundary_id": "SEC-07",
            "name": "Registry Sentinel Protection",
            "passed": True,
            "details": "Direct tool invocation importing _REGISTRY_GATE_SENTINEL returned policy_denied=True",
        })
        print(" [PASS] SEC-07: Registry Sentinel Protection")
    except Exception as e:
        results.append({"boundary_id": "SEC-07", "name": "Registry Sentinel Protection", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-07: {e}")

    # -------------------------------------------------------------
    # 8. First-run Credential & Password Change Enforcement
    # -------------------------------------------------------------
    try:
        sec_db = PROJECT_ROOT / "research" / "phase7" / "phase7_pwd_test.db"
        if sec_db.exists():
            sec_db.unlink()
        sec_store = EvidenceStore(str(sec_db))
        sec_auth = AuthenticationService(store=sec_store)
        admin = sec_auth.bootstrap_admin("init_admin", "RandomInitPassword123!@#", must_change_password=True)
        assert admin["must_change_password"] is True, "Initial admin must have must_change_password=True"
        is_locked = sec_auth.is_setup_completed()
        assert is_locked, "Initial setup lock was not set in system_settings"
        double_boot = False
        try:
            sec_auth.bootstrap_admin("admin2", "Pass2!")
        except RuntimeError:
            double_boot = True
        assert double_boot, "Silent administrator recreation was allowed!"
        results.append({
            "boundary_id": "SEC-08",
            "name": "First-run Credential & Password Change Gating",
            "passed": True,
            "details": "must_change_password=True enforced, system_settings setup lock prevents silent recreation",
        })
        print(" [PASS] SEC-08: First-run Credential & Password Change Gating")
    except Exception as e:
        results.append({"boundary_id": "SEC-08", "name": "First-run Credential & Password Change Gating", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-08: {e}")

    # -------------------------------------------------------------
    # 9. Cryptographic Evidence Integrity
    # -------------------------------------------------------------
    try:
        sec_store.create_session("sec_sess_1", "Security Assessment")
        log_id = sec_store.log_traffic(
            session_id="sec_sess_1",
            method="GET",
            url="http://127.0.0.1:8080/api/users",
            headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="{'users': ['alice', 'bob']}",
        )
        sec_store.record_finding(
            session_id="sec_sess_1",
            endpoint="/api/users",
            category="Sensitive Data Exposure",
            status="CONFIRMED",
            evidence_notes="Initial uncorrupted payload",
            traffic_log_id=log_id,
            severity="HIGH",
        )
        int_valid = sec_store.verify_evidence_integrity("sec_sess_1")
        assert int_valid["verified"], f"Initial integrity check failed: {int_valid}"

        # Tamper directly in traffic_log database record
        with sqlite3.connect(str(sec_db)) as conn:
            conn.execute("UPDATE traffic_log SET response_body = 'tampered body' WHERE id = ?", (log_id,))
            conn.commit()

        int_tampered = sec_store.verify_evidence_integrity("sec_sess_1")
        assert not int_tampered["verified"], "Tampered traffic record was not detected!"
        assert log_id in int_tampered["tampered_records"]
        results.append({
            "boundary_id": "SEC-09",
            "name": "Cryptographic Evidence Tamper Detection",
            "passed": True,
            "details": f"SHA-256 evidence integrity check flagged modified traffic_log ID {log_id} as tampered",
        })
        print(" [PASS] SEC-09: Cryptographic Evidence Tamper Detection")
    except Exception as e:
        results.append({"boundary_id": "SEC-09", "name": "Cryptographic Evidence Tamper Detection", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-09: {e}")

    # -------------------------------------------------------------
    # 10. Unregistered Tool Invocation Blocking
    # -------------------------------------------------------------
    try:
        pe_tools = PolicyEngine(registered_tools={"http_request", "parameter_fuzzer"})
        dec_unreg = pe_tools.evaluate_action("system_command_exec", {"cmd": "rm -rf /"})
        assert not dec_unreg.approved, "Unregistered tool was approved!"
        assert "not in the authorized tool registry" in dec_unreg.reason
        results.append({
            "boundary_id": "SEC-10",
            "name": "Unregistered Tool Rejection",
            "passed": True,
            "details": f"Blocked unregistered tool: {dec_unreg.reason}",
        })
        print(" [PASS] SEC-10: Unregistered Tool Rejection")
    except Exception as e:
        results.append({"boundary_id": "SEC-10", "name": "Unregistered Tool Rejection", "passed": False, "error": str(e)})
        print(f" [FAIL] SEC-10: {e}")

    print("=" * 78)
    passed_count = sum(1 for r in results if r["passed"])
    print(f" SECURITY BOUNDARY RESULTS: {passed_count}/{len(results)} PASSED")
    print("=" * 78)

    output_data = {
        "timestamp": time.time(),
        "total_boundaries_evaluated": len(results),
        "passed_boundaries_count": passed_count,
        "all_boundaries_passed": passed_count == len(results),
        "results": results,
    }

    out_path = PROJECT_ROOT / "research" / "phase7" / "security_validation_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"[*] Results saved to {out_path}\n")
    return output_data


if __name__ == "__main__":
    run_security_boundary_tests()
