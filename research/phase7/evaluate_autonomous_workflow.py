"""Phase 7.0: Autonomous Workflow Evaluation on Local Lab with Real CPU Model.

Evaluates the complete AutonomousController against the Vulnerable API Lab
using the real Qwen2.5-1.5B Q4_K_M GGUF model (strictly non-mock).

Measures:
- Successful test execution rate
- Tool selection accuracy and reasoning
- Valid evidence generation and hashing
- Verified vulnerability findings (OWASP API Top 10)
- Average tool calls and HTTP requests per assessment
- Budget stopping-condition enforcement
- Execution duration and latency
"""

import json
import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller.agent.autonomous_controller import AutonomousController
from controller.auth.authentication_service import AuthenticationService
from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model
from controller.config import AgentConfig
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.policy_service import PolicyService
from controller.reporting.report_generator import ReportGenerator
from controller.storage.evidence_store import EvidenceStore
from controller.tools import build_default_tool_registry
from lab.app import create_app as create_lab_app
from lab.database import LabDatabase
from werkzeug.serving import make_server


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LabServerContext:
    """Manages local vulnerable API lab in background daemon thread."""

    def __init__(self, host: str, port: int, db_path: Path):
        self.host = host
        self.port = port
        self.db_path = db_path
        self.server = None
        self.thread = None

    def __enter__(self):
        lab_db = LabDatabase(str(self.db_path))
        app = create_lab_app(db=lab_db)
        self.server = make_server(self.host, self.port, app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Wait for port
        start = time.time()
        while time.time() - start < 5.0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex((self.host, self.port)) == 0:
                    return self
            time.sleep(0.1)
        raise RuntimeError(f"Lab server failed to start on port {self.port}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.server:
            self.server.shutdown()


def run_scenario(scenario_id: str, name: str, lab_port: int, max_turns: int, max_requests: int, store: EvidenceStore, policy_svc: PolicyService, brain: LocalCpuBrainClient):
    print(f"\n[*] Executing Scenario {scenario_id}: {name}")
    print(f"    Target: http://127.0.0.1:{lab_port} | Max Turns: {max_turns} | Max Requests: {max_requests}")

    # Create policy with exact target authorization
    pol = policy_svc.create_policy(
        name=f"Phase 7 Policy - {name}",
        config={
            "max_requests": max_requests,
            "max_turns": max_turns,
            "allowed_tools": [
                "http_request", "httpx_request", "openapi_parser", "jwt_inspector",
                "parameter_fuzzer", "zap_scanner", "graphql_probe", "inventory_scanner",
                "business_flow_probe"
            ],
        },
        creator_id=1,
        targets=[{"host_pattern": "127.0.0.1", "port_range": str(lab_port), "path_prefix": "/"}],
    )
    policy_id = pol["id"]

    registry = build_default_tool_registry()
    config = AgentConfig(
        max_turns=max_turns,
        max_requests_per_session=max_requests,
        allowed_hosts={"127.0.0.1", "localhost"},
    )
    controller = AutonomousController(
        config=config,
        model_brain=brain,
        tool_registry=registry,
        evidence_store=store,
        policy_service=policy_svc,
    )

    t0 = time.time()
    res = controller.run_assessment(
        target_url=f"http://127.0.0.1:{lab_port}",
        session_notes=f"Phase 7.0 Academic Evaluation - {name}",
        policy_id=policy_id,
    )
    duration = time.time() - t0
    session_id = res.get("session_id")
    if not session_id:
        raise RuntimeError(f"Assessment failed to return session_id: {res}")

    # Retrieve execution metrics from evidence store
    findings = store.get_findings(session_id)
    verified_findings = [f for f in findings if f.get("status") in ("CONFIRMED", "VERIFIED")]
    suspected_findings = [f for f in findings if f.get("status") == "SUSPECTED"]

    traffic = store.get_traffic_logs(session_id)
    tool_execs = store.get_tool_executions(session_id)
    integrity = store.verify_evidence_integrity(session_id)

    # Check budget enforcement
    requests_sent = len(traffic)
    budget_respected = requests_sent <= max_requests

    print(f" [+] Session Completed: {session_id} in {duration:.2f}s")
    print(f" [+] Tool Calls Executed: {len(tool_execs)} | HTTP Traffic: {requests_sent}/{max_requests}")
    print(f" [+] Findings Discovered: {len(findings)} total ({len(verified_findings)} verified, {len(suspected_findings)} suspected)")
    print(f" [+] Evidence Hash Verified: {integrity['verified']} (tampered: {len(integrity['tampered_records'])})")
    print(f" [+] Budget Respected: {budget_respected}")

    # Inspect model reasoning in tool executions
    tool_names = [te["tool_name"] for te in tool_execs]
    print(f" [+] Tool Sequence: {' -> '.join(tool_names)}")

    return {
        "scenario_id": scenario_id,
        "name": name,
        "session_id": session_id,
        "target_url": f"http://127.0.0.1:{lab_port}",
        "max_turns": max_turns,
        "max_requests": max_requests,
        "duration_seconds": round(duration, 2),
        "requests_sent": requests_sent,
        "budget_enforced": budget_respected,
        "tool_executions_count": len(tool_execs),
        "tool_sequence": tool_names,
        "total_findings": len(findings),
        "verified_findings_count": len(verified_findings),
        "suspected_findings_count": len(suspected_findings),
        "verified_findings": [
            {
                "id": f["id"],
                "category": f.get("category"),
                "endpoint": f.get("endpoint"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "evidence_notes": f.get("evidence_notes"),
                "evidence_hash": f.get("evidence_hash"),
            }
            for f in verified_findings
        ],
        "evidence_integrity": integrity,
    }


def main():
    print("=" * 78)
    print("   PHASE 7.0: AUTONOMOUS WORKFLOW EMPIRICAL EVALUATION")
    print("=" * 78)

    model_path = find_default_gguf_model()
    print(f"[*] Target Model: {model_path}")
    assert model_path and os.path.exists(model_path)

    # Strictly non-mock real CPU client
    brain = LocalCpuBrainClient(model_path=model_path, allow_mock_fallback=False, n_threads=4)
    print(f"[*] Brain Client: engine='{brain.engine}', is_mock={brain.is_mock}")
    assert brain.engine == "llama_cli" and not brain.is_mock

    db_path = PROJECT_ROOT / "research" / "phase7" / "phase7_lab_evidence.db"
    if db_path.exists():
        db_path.unlink()

    store = EvidenceStore(str(db_path))
    auth_svc = AuthenticationService(store=store)
    auth_svc.bootstrap_admin("eval_admin", "EvalAdminPass2026!#", force_setup=True)
    policy_svc = PolicyService(store=store)

    lab_port = find_free_port()
    lab_db_path = PROJECT_ROOT / "research" / "phase7" / "phase7_vulnerable_lab.db"
    if lab_db_path.exists():
        lab_db_path.unlink()

    with LabServerContext("127.0.0.1", lab_port, lab_db_path):
        print(f"[*] Live Vulnerable API Lab active on http://127.0.0.1:{lab_port}")

        # Scenario 1: Standard multi-turn autonomous exploration (turns=5, requests=20)
        s1 = run_scenario("SCENARIO-1", "Standard Multi-Turn Vulnerability Discovery", lab_port, max_turns=5, max_requests=20, store=store, policy_svc=policy_svc, brain=brain)

        # Scenario 2: Strict request budget hard cutoff (turns=10, requests=5)
        s2 = run_scenario("SCENARIO-2", "Strict Budget Hard-Cutoff Enforcement", lab_port, max_turns=10, max_requests=5, store=store, policy_svc=policy_svc, brain=brain)

        # Scenario 3: Negative control / restricted endpoint probe (turns=3, requests=10)
        s3 = run_scenario("SCENARIO-3", "Restricted Endpoint Probing", lab_port, max_turns=3, max_requests=10, store=store, policy_svc=policy_svc, brain=brain)

    all_scenarios = [s1, s2, s3]
    total_findings = sum(s["total_findings"] for s in all_scenarios)
    total_verified = sum(s["verified_findings_count"] for s in all_scenarios)
    total_traffic = sum(s["requests_sent"] for s in all_scenarios)
    all_budgets_ok = all(s["budget_enforced"] for s in all_scenarios)
    all_integrity_ok = all(s["evidence_integrity"]["verified"] for s in all_scenarios)

    summary = {
        "evaluation_timestamp": time.time(),
        "model_engine": brain.engine,
        "is_mock": brain.is_mock,
        "total_scenarios_evaluated": len(all_scenarios),
        "total_duration_seconds": round(sum(s["duration_seconds"] for s in all_scenarios), 2),
        "metrics": {
            "total_requests_executed": total_traffic,
            "total_findings_recorded": total_findings,
            "total_verified_findings": total_verified,
            "all_budgets_respected": all_budgets_ok,
            "all_evidence_verified": all_integrity_ok,
            "average_tool_calls_per_assessment": round(sum(s["tool_executions_count"] for s in all_scenarios) / len(all_scenarios), 1),
            "average_completion_time_seconds": round(sum(s["duration_seconds"] for s in all_scenarios) / len(all_scenarios), 2),
        },
        "scenarios": all_scenarios,
    }

    out_file = PROJECT_ROOT / "research" / "phase7" / "autonomous_workflow_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 78)
    print("   AUTONOMOUS WORKFLOW EVALUATION COMPLETE")
    print("=" * 78)
    print(f" Scenarios Tested        : {len(all_scenarios)}")
    print(f" Total Findings Verified : {total_verified}")
    print(f" Budget Hard Cutoff      : {'PASSED (Zero Overrun)' if all_budgets_ok else 'FAILED'}")
    print(f" Evidence Cryptographic  : {'100% VERIFIED' if all_integrity_ok else 'FAILED'}")
    print(f" Results Saved To        : {out_file}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
