"""OWASP ZAP Integration & Autonomous Penetration Testing Demo.

Demonstrates:
1. Spawning the local vulnerable lab on http://127.0.0.1:5050.
2. Checking local OWASP ZAP daemon status (http://127.0.0.1:8080).
3. If real ZAP is online:
   - Initiates spider crawling on the target.
   - Drains passive scan records.
   - Retrieves security alerts and correlates them into the SQLite evidence store.
   - Enforces the invariant: findings default to SUSPECTED unless an approved verification rule applies.
4. If real ZAP is offline:
   - Demonstrates graceful fallback without crashing.
   - Provides exact instructions for launching ZAP locally.
   - Demonstrates the mock ZAP REST adapter.
5. Generates an executive Markdown audit report.
"""

import json
import os
import sys
import threading
import time
from typing import Dict, Any

import requests
from werkzeug.serving import make_server

# Adjust workspace root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lab.app import create_app
from lab.database import LabDatabase
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.storage.evidence_store import EvidenceStore
from controller.tools.zap_client import ZapSecurityScanTool
from controller.reporting.report_generator import ReportGenerator


class LabServerThread(threading.Thread):
    def __init__(self, app, host: str = "127.0.0.1", port: int = 5050):
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


def run_zap_demo():
    print("=" * 75)
    print("PHASE 3: OWASP ZAP & AUTONOMOUS AGENT INTEGRATION DEMO")
    print("=" * 75)

    # 1. Start Local Vulnerable Lab
    lab_db = LabDatabase(":memory:")
    lab_app = create_app(lab_db)
    port = 5050
    server_thread = LabServerThread(lab_app, host="127.0.0.1", port=port)
    server_thread.start()
    target_base = f"http://127.0.0.1:{port}"
    print(f"[*] Local API Security Lab running on {target_base}")
    time.sleep(0.5)

    # 2. Check ZAP Daemon Status
    zap_tool = ZapSecurityScanTool()
    health = zap_tool.execute(action="check_health")

    reports_dir = os.path.join(PROJECT_ROOT, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    db_path = os.path.join(reports_dir, "phase3_zap_demo_evidence.db")
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    store = EvidenceStore(db_path=db_path)
    config = AgentConfig(
        max_turns=12,
        max_requests_per_session=25,
        db_path=db_path,
        zap_base_url="http://127.0.0.1:8080",
        zap_active_scan_enabled=False,  # Safe by default
    )
    brain = DeterministicMockBrainClient()
    controller = AutonomousController(
        config=config,
        model_brain=brain,
        evidence_store=store,
    )

    if health.get("connected"):
        print(f"[+] OWASP ZAP Daemon detected ONLINE! Version: {health.get('version')}")
        print(f"[*] Base URL: {config.zap_base_url}")
        print("[*] Active Scanning status: DISABLED (Safe default)")

        session_id = f"zap_live_session_{int(time.time())}"
        store.create_session(session_id, target_base, notes="Live OWASP ZAP Demonstration")

        # Run Spider
        print(f"[*] Triggering ZAP Spider crawl against {target_base}...")
        spider_res = zap_tool.execute(
            action="spider",
            url=target_base,
            poll_until_complete=True,
            poll_timeout=15.0,
        )
        print(f"[+] Spider Finished. Status: {spider_res.get('status', 'DONE')}")
        if spider_res.get("discovered_urls"):
            print(f"    - Discovered {len(spider_res['discovered_urls'])} URLs")

        # Fetch Alerts
        alerts_res = zap_tool.execute(action="get_alerts", url=target_base)
        alerts = alerts_res.get("alerts", [])
        print(f"[+] ZAP Alerts Retrieved: {len(alerts)}")

        # Store ZAP Scan Metadata
        store.record_zap_scan(
            session_id=session_id,
            scan_id=spider_res.get("scan_id", "1"),
            scan_type="spider",
            target_url=target_base,
            status="COMPLETED",
            alert_count=len(alerts),
            raw_alerts=alerts,
        )

        for alert in alerts:
            fid, fstatus, is_new = store.correlate_and_record_zap_finding(
                session_id=session_id,
                alert=alert,
                zap_scan_id=spider_res.get("scan_id", "1"),
            )
            print(f"    - Alert [{fstatus}]: {alert.get('name')} (Risk: {alert.get('risk')})")

    else:
        print("[-] OWASP ZAP Daemon is OFFLINE at http://127.0.0.1:8080.")
        print("    " + "-" * 65)
        print("    To launch OWASP ZAP in daemon mode on Windows:")
        print("    1. Open PowerShell or Command Prompt.")
        print("    2. Navigate to your OWASP ZAP installation folder.")
        print(r'       e.g., cd "C:\Program Files\OWASP\Zed Attack Proxy"')
        print("    3. Launch daemon with disabled API key for localhost lab:")
        print("       .\\zap.bat -daemon -port 8080 -config api.disablekey=true")
        print("    " + "-" * 65)
        print("[*] Running simulated autonomous controller assessment with Mock ZAP adapter...")

        # Run standard autonomous assessment loop
        result = controller.run_assessment(
            target_url=target_base,
            spec_source=f"{target_base}/openapi.json",
            session_notes="Simulated ZAP fallback assessment",
        )
        session_id = result["session_id"]

    # Generate Markdown Report
    generator = ReportGenerator(evidence_store=store)
    full_report = generator.generate_report(session_id)
    report_file = os.path.join(reports_dir, f"{session_id}_zap_report.md")
    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write(full_report)

    print(f"\n[+] Audit Report written to: {report_file}")

    # Shutdown
    server_thread.shutdown()
    print("[*] Local API Lab server shut down cleanly.\n")


if __name__ == "__main__":
    run_zap_demo()

