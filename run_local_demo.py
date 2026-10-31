"""Phase 2 Local Lab Autonomous Penetration Testing Demonstration.

Executes an end-to-end autonomous security assessment against the local vulnerable API lab
running on 127.0.0.1. Validates the complete feedback loop:
Target Authorization -> Test Planning -> Action Selection -> Policy Guardrails ->
Tool Execution -> SQLite Evidence Storage -> Evidence Analysis -> Markdown Reporting.
"""

import os
import sys
import threading
import time
from typing import Dict, Any

import requests
from werkzeug.serving import make_server

from lab.app import create_app
from lab.database import LabDatabase
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.storage.evidence_store import EvidenceStore
from controller.reporting.report_generator import ReportGenerator


class ServerThread(threading.Thread):
    """Manages local Flask lab server in a background thread with clean shutdown."""

    def __init__(self, app, host: str = "127.0.0.1", port: int = 5000):
        super().__init__()
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.daemon = True
        self.port = port
        self.host = host

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def run_phase2_demo():
    print("=" * 75)
    print("PHASE 2: AUTONOMOUS API PENETRATION TESTING DEMO (LOCAL LAB)")
    print("=" * 75)

    # 1. Start Local API Lab
    lab_db = LabDatabase(":memory:")
    lab_app = create_app(lab_db)
    port = 5050
    server_thread = ServerThread(lab_app, host="127.0.0.1", port=port)
    server_thread.start()
    target_base = f"http://127.0.0.1:{port}"

    print(f"[*] Local API Security Lab started on {target_base}")
    time.sleep(0.5)

    # Verify Health
    health_resp = requests.get(f"{target_base}/health", timeout=2.0)
    print(f"[+] Health Check: {health_resp.status_code} - {health_resp.json()}")

    # 2. Configure Autonomous Controller & Storage
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    db_path = os.path.join(reports_dir, "phase2_demo_evidence.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    store = EvidenceStore(db_path=db_path)
    config = AgentConfig(
        max_turns=12,
        max_requests_per_session=20,
        db_path=db_path,
    )
    brain = DeterministicMockBrainClient()
    controller = AutonomousController(
        config=config,
        model_brain=brain,
        evidence_store=store,
    )

    # 3. Define Lab Target Endpoints to Evaluate (with live OpenAPI discovery)
    spec_url = f"{target_base}/openapi.json"
    print(f"[*] Discovering API specification live from: {spec_url}")

    # Fallback/default endpoints with targeted payload templates if needed
    fallback_endpoints = [
        {"path": "/health", "method": "GET"},
        {"path": "/api/users", "method": "GET"},
        {"path": "/api/users/2", "method": "GET"},
        {"path": "/api/login", "method": "POST", "body": {"username": "admin", "password": ""}},
        {"path": "/api/users/1", "method": "PUT", "body": {"role": "admin", "is_admin": 1}},
        {"path": "/api/search?q='", "method": "GET"},
        {"path": "/api/items", "method": "GET"},
    ]

    print("\n[*] Initializing Autonomous Controller Loop...")
    print(f"[*] Target Scope: {target_base} (Authorized Localhost Only)")

    # 4. Run Autonomous Assessment with OpenAPI Discovery
    start_time = time.time()
    result = controller.run_assessment(
        target_url=target_base,
        endpoints=fallback_endpoints,
        spec_source=spec_url,
        session_notes="Phase 2 OpenAPI Discovery and HTTPX Validation",
    )
    elapsed = round(time.time() - start_time, 2)

    session_id = result["session_id"]
    specs = store.get_specifications(session_id)
    print(f"\n[+] Assessment Complete in {elapsed}s!")
    print(f"    - Session ID: {session_id}")
    if specs:
        print(f"    - OpenAPI Title: {specs[0]['title']} (v{specs[0]['spec_version']})")
        print(f"    - Discovered Endpoints: {specs[0]['endpoints_count']}")
    print(f"    - Turns Taken: {result['turns_taken']}")
    print(f"    - Total Requests Dispatched: {result['requests_sent']}")
    print(f"    - Termination Reason: {result['termination_reason']}")

    # 5. Display Recorded Findings
    findings = store.get_findings(session_id)
    print(f"\n[+] Security Findings Recorded ({len(findings)}):")
    print("-" * 75)
    print(f"{'ID':<4} | {'Status':<12} | {'Category':<22} | {'Verification Rule'}")
    print("-" * 75)
    for f in findings:
        rule = f.get("verification_rule") or "None"
        print(f"{f['id']:<4} | {f['status']:<12} | {f['category']:<22} | {rule}")

    # 6. Generate and Save Comprehensive Markdown Report
    generator = ReportGenerator(evidence_store=store)
    full_report = generator.generate_report(session_id)
    report_file = os.path.join(reports_dir, f"{session_id}_report.md")
    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write(full_report)

    print(f"\n[+] Audit Report written to: {report_file}")

    # 7. Clean Shutdown
    server_thread.shutdown()
    print("[*] Local API Lab server shut down cleanly.\n")

    return result, report_file


if __name__ == "__main__":
    run_phase2_demo()
