"""Phase 2 Kaggle GPU Inference Entry Point for Qwen2.5-1.5B + RebuiltV4 Adapter.

Executes autonomous API penetration testing using the REAL fine-tuned Qwen model
and RebuiltV4 Checkpoint-200 adapter on a Kaggle Tesla T4 GPU instance.

This script:
1. Spawns the local vulnerable API lab on http://127.0.0.1:5000 in a daemon thread.
2. Loads Qwen/Qwen2.5-1.5B-Instruct and attaches RebuiltV4 Checkpoint-200 LoRA weights.
3. Wires the live LocalQwenBrainClient into the deterministic AutonomousController.
4. Executes the autonomous ReAct testing loop (Planning -> Actions -> Guardrails -> Tools -> Storage -> Reporting).
5. Persists traffic logs, execution receipts, and verified findings in SQLite.
6. Outputs a comprehensive Markdown audit report.
"""

import os
import sys
import threading
import time
from typing import Dict, Any

from werkzeug.serving import make_server

# Workspace path resolution
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lab.app import create_app
from lab.database import LabDatabase
from controller.config import AgentConfig
from controller.agent.autonomous_controller import AutonomousController
from controller.brain.model_gateway import LocalQwenBrainClient
from controller.storage.evidence_store import EvidenceStore
from controller.reporting.report_generator import ReportGenerator


class LabServerThread(threading.Thread):
    """Background runner for the local API lab."""

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


def resolve_adapter_path() -> str:
    """Resolve path to RebuiltV4 Checkpoint-200 in both local and Kaggle environments."""
    # Kaggle dataset input paths
    kaggle_paths = [
        "/kaggle/input/rebuiltv4-checkpoints/checkpoint-200",
        "/kaggle/input/api-security-recovery/staging_rebuiltv4_training_checkpoints/checkpoint-200",
        "/kaggle/working/checkpoint-200",
    ]
    for p in kaggle_paths:
        if os.path.exists(p):
            return p

    # Local workspace path
    local_path = os.path.join(PROJECT_ROOT, "staging_rebuiltv4_training_checkpoints", "checkpoint-200")
    if os.path.exists(local_path):
        return local_path

    raise FileNotFoundError("Could not find RebuiltV4 Checkpoint-200 adapter directory.")


def main():
    print("=" * 80)
    print("AUTONOMOUS API SECURITY TESTING AGENT - KAGGLE GPU LIVE QWEN INFERENCE")
    print("=" * 80)

    # 1. Start Local API Lab
    lab_port = 5050
    lab_db = LabDatabase(":memory:")
    lab_app = create_app(lab_db)
    server = LabServerThread(lab_app, host="127.0.0.1", port=lab_port)
    server.start()
    target_url = f"http://127.0.0.1:{lab_port}"
    print(f"[*] Local API Security Lab running on {target_url}")
    time.sleep(0.5)

    # 2. Locate and Load RebuiltV4 Adapter with Qwen Base Model
    adapter_dir = resolve_adapter_path()
    print(f"[*] Resolved RebuiltV4 Checkpoint-200 Adapter: {adapter_dir}")
    print("[*] Initializing LocalQwenBrainClient on GPU...")

    try:
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"[*] PyTorch Device: {device} (CUDA available: {torch.cuda.is_available()})")
        if device == "cuda":
            print(f"[*] GPU Name: {torch.cuda.get_device_name(0)}")
            print(f"[*] Allocated VRAM: {round(torch.cuda.memory_allocated() / 1e9, 2)} GB")

        brain = LocalQwenBrainClient(
            base_model_name="Qwen/Qwen2.5-1.5B-Instruct",
            adapter_path=adapter_dir,
            device=device,
        )
        print("[+] Qwen2.5-1.5B-Instruct + RebuiltV4 Checkpoint-200 loaded successfully!")

    except Exception as exc:
        print(f"[!] Failed to load live Qwen brain: {exc}")
        print("[!] Ensure torch, transformers, and peft are installed with GPU acceleration.")
        server.shutdown()
        sys.exit(1)

    # 3. Configure Evidence Store and Controller
    output_dir = "/kaggle/working" if os.path.exists("/kaggle/working") else os.path.join(PROJECT_ROOT, "reports")
    os.makedirs(output_dir, exist_ok=True)
    db_file = os.path.join(output_dir, "kaggle_live_qwen_evidence.db")
    if os.path.exists(db_file):
        os.remove(db_file)

    store = EvidenceStore(db_path=db_file)
    config = AgentConfig(
        max_turns=10,
        max_requests_per_session=25,
        db_path=db_file,
    )

    controller = AutonomousController(
        config=config,
        model_brain=brain,
        evidence_store=store,
    )

    # 4. Target Endpoints for Assessment
    endpoints = [
        {"path": "/health", "method": "GET"},
        {"path": "/api/users", "method": "GET"},
        {"path": "/api/users/2", "method": "GET"},
        {"path": "/api/login", "method": "POST", "body": {"username": "admin", "password": ""}},
        {"path": "/api/users/1", "method": "PUT", "body": {"role": "admin", "is_admin": 1}},
        {"path": "/api/search?q='", "method": "GET"},
        {"path": "/api/items", "method": "GET"},
    ]

    print("\n[*] Starting Autonomous Testing Loop driven by Qwen Brain...")
    start_time = time.time()
    result = controller.run_assessment(
        target_url=target_url,
        endpoints=endpoints,
        session_notes="Kaggle Live GPU Execution with Qwen2.5-1.5B RebuiltV4",
    )
    duration = round(time.time() - start_time, 2)

    session_id = result["session_id"]
    print(f"\n[+] Assessment Finished in {duration}s!")
    print(f"    - Session ID: {session_id}")
    print(f"    - Turns Taken: {result['turns_taken']}")
    print(f"    - Total Requests Dispatched: {result['requests_sent']}")
    print(f"    - Termination Reason: {result['termination_reason']}")

    # 5. Report Findings
    findings = store.get_findings(session_id)
    print(f"\n[+] Security Findings Recorded ({len(findings)}):")
    print("-" * 75)
    for f in findings:
        print(f"[{f['status']}] {f['category']} at {f['endpoint']} (Rule: {f.get('verification_rule')})")

    # 6. Save Markdown Report
    report_path = os.path.join(output_dir, f"kaggle_qwen_assessment_{session_id}.md")
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write(result["report_markdown"])
    print(f"\n[+] Comprehensive Report written to: {report_path}")

    # 7. Shutdown
    server.shutdown()
    print("[*] Local lab shutdown complete.")


if __name__ == "__main__":
    main()

