"""Phase 4: Autonomous API Penetration Testing Agent with Live Qwen Model Inference.

Executes autonomous penetration testing against the local vulnerable API laboratory
using the real Qwen/Qwen2.5-1.5B-Instruct base model and RebuiltV4 Checkpoint-200 LoRA adapter
with 4-bit NF4 quantization on a Kaggle Tesla T4 GPU instance.

This script demonstrates the complete feedback loop:
1. Spawns local vulnerable lab on http://127.0.0.1:5050 with OpenAPI 3.x discovery.
2. Loads 4-bit NF4 quantized Qwen2.5-1.5B-Instruct + RebuiltV4 Checkpoint-200 on GPU.
3. Wires LocalQwenBrainClient into the deterministic AutonomousController.
4. Executes the autonomous ReAct testing loop:
   - Target Authorization -> OpenAPI Discovery -> Qwen Planning -> Action Proposal ->
     Policy Guardrails -> HTTPX / ZAP Execution -> Evidence Storage -> Qwen Evidence Analysis ->
     Safe Abstention / Next Action Loop -> Markdown Reporting.
5. Measures and logs exact GPU VRAM footprint, token counts, decision validity, and abstentions.
"""

import argparse
import json
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from werkzeug.serving import make_server

# Adjust path for workspace resolution
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
    """Background thread managing the local vulnerable API lab."""

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


def resolve_adapter_path() -> str:
    """Locate RebuiltV4 Checkpoint-200 adapter directory across environments."""
    candidates = [
        "/kaggle/input/rebuiltv4-training-checkpoints/checkpoint-200",
        "/kaggle/input/rebuiltv4-adapters/checkpoint-200",
        "/kaggle/input/api-security-recovery/staging_rebuiltv4_training_checkpoints/checkpoint-200",
        os.path.join(PROJECT_ROOT, "staging_rebuiltv4_training_checkpoints", "checkpoint-200"),
    ]
    for path in candidates:
        if os.path.exists(path) and os.path.exists(os.path.join(path, "adapter_config.json")):
            return path
    raise FileNotFoundError(
        "Could not locate RebuiltV4 Checkpoint-200 adapter directory with adapter_config.json."
    )


def run_gpu_autonomous_assessment(
    max_turns: int = 10,
    max_requests: int = 25,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete Phase 4 live model autonomous security assessment."""
    print("=" * 80)
    print("PHASE 4: LIVE QWEN2.5-1.5B AUTONOMOUS API PENETRATION TESTING")
    print("=" * 80)

    # 1. Start Local API Laboratory
    lab_port = 5050
    lab_db = LabDatabase(":memory:")
    lab_app = create_app(lab_db)
    server_thread = LabServerThread(lab_app, host="127.0.0.1", port=lab_port)
    server_thread.start()
    target_base = f"http://127.0.0.1:{lab_port}"
    print(f"[*] Local Vulnerable API Lab started on {target_base}")
    time.sleep(0.5)

    # 2. Check GPU Environment & Memory Baseline
    try:
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"[*] Execution Device: {device.upper()}")
        if device == "cuda":
            print(f"[*] GPU Model: {torch.cuda.get_device_name(0)}")
            print(f"[*] Initial VRAM: {round(torch.cuda.memory_allocated() / 1e9, 3)} GB")
    except ImportError:
        device = "cpu"
        print("[!] PyTorch not found. LocalQwenBrainClient requires PyTorch on GPU.")

    # 3. Locate Adapter & Load Live Model with 4-bit NF4 Quantization
    adapter_path = resolve_adapter_path()
    print(f"[*] Resolved RebuiltV4 Checkpoint-200 Adapter: {adapter_path}")
    print("[*] Loading Qwen/Qwen2.5-1.5B-Instruct (4-bit NF4 Quantization via BitsAndBytesConfig)...")

    load_start = time.time()
    brain = LocalQwenBrainClient(
        base_model_name="Qwen/Qwen2.5-1.5B-Instruct",
        adapter_path=adapter_path,
        device=device,
        load_in_4bit=True,
    )
    load_time = round(time.time() - load_start, 2)
    print(f"[+] Model + Adapter loaded in {load_time}s!")

    if device == "cuda":
        allocated_vram = round(torch.cuda.memory_allocated() / 1e9, 3)
        reserved_vram = round(torch.cuda.memory_reserved() / 1e9, 3)
        print(f"[*] Post-Load Allocated VRAM: {allocated_vram} GB (Reserved: {reserved_vram} GB)")

    # 4. Set Up Evidence Store and Autonomous Controller
    out_dir = output_dir or ("/kaggle/working" if os.path.exists("/kaggle/working") else os.path.join(PROJECT_ROOT, "reports"))
    os.makedirs(out_dir, exist_ok=True)
    db_file = os.path.join(out_dir, "phase4_live_qwen_evidence.db")
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass

    store = EvidenceStore(db_path=db_file)
    config = AgentConfig(
        max_turns=max_turns,
        max_requests_per_session=max_requests,
        db_path=db_file,
    )
    controller = AutonomousController(
        config=config,
        model_brain=brain,
        evidence_store=store,
    )

    # 5. Execute Live Assessment with OpenAPI Specification Discovery
    spec_url = f"{target_base}/openapi.json"
    print(f"\n[*] Initiating Autonomous Assessment against {target_base}")
    print(f"[*] Discovering API specification from: {spec_url}")
    print(f"[*] Loop Limits: Max {max_turns} turns, Max {max_requests} HTTP requests")

    eval_start = time.time()
    result = controller.run_assessment(
        target_url=target_base,
        spec_source=spec_url,
        session_notes="Phase 4 Live Qwen2.5-1.5B + RebuiltV4 Checkpoint-200 GPU Assessment",
    )
    total_eval_time = round(time.time() - eval_start, 2)

    session_id = result["session_id"]
    print(f"\n[+] Autonomous Assessment Loop Complete in {total_eval_time}s!")
    print(f"    - Session ID: {session_id}")
    print(f"    - Turns Taken: {result['turns_taken']}")
    print(f"    - Total Requests Dispatched: {result['requests_sent']}")
    print(f"    - Termination Reason: {result['termination_reason']}")

    # 6. Display Model Decision Performance & VRAM Metrics
    metrics = brain.metrics
    print("\n[+] Live Qwen Brain Inference Metrics:")
    print(f"    - Total Model Inferences: {metrics.get('total_inferences', 0)}")
    print(f"    - Valid Structured Decisions: {metrics.get('valid_decisions', 0)}")
    print(f"    - Invalid Decisions / Fallbacks: {metrics.get('invalid_decisions', 0)}")
    print(f"    - Safe Abstentions (no_action / complete): {metrics.get('abstentions', 0)}")
    print(f"    - Total Prompt Tokens: {metrics.get('total_prompt_tokens', 0)}")
    print(f"    - Total Completion Tokens: {metrics.get('total_completion_tokens', 0)}")
    print(f"    - Total Generation Latency: {metrics.get('total_latency_seconds', 0.0)}s")

    # 7. Security Findings Summary
    findings = store.get_findings(session_id)
    print(f"\n[+] Security Findings Recorded ({len(findings)}):")
    print("-" * 80)
    print(f"{'ID':<4} | {'Status':<12} | {'Category':<24} | {'Verification Rule'}")
    print("-" * 80)
    for f in findings:
        print(f"{f['id']:<4} | {f['status']:<12} | {f['category']:<24} | {f.get('verification_rule') or 'None'}")

    # 8. Save Comprehensive Markdown Audit Report
    report_file = os.path.join(out_dir, f"phase4_qwen_assessment_{session_id}.md")
    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write(result["report_markdown"])
    print(f"\n[+] Comprehensive Audit Report saved to: {report_file}")

    # 9. Clean Shutdown
    server_thread.shutdown()
    print("[*] Local API laboratory shut down cleanly.\n")

    return {
        "session_id": session_id,
        "turns_taken": result["turns_taken"],
        "requests_sent": result["requests_sent"],
        "findings_count": len(findings),
        "metrics": metrics,
        "report_file": report_file,
    }


def main():
    parser = argparse.ArgumentParser(description="Phase 4: Qwen Model Autonomous Pentest Runner")
    parser.add_argument("--max-turns", type=int, default=10, help="Maximum execution turns")
    parser.add_argument("--max-requests", type=int, default=25, help="Maximum HTTP requests")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory for reports and SQLite DB")
    args = parser.parse_args()

    run_gpu_autonomous_assessment(
        max_turns=args.max_turns,
        max_requests=args.max_requests,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()

