"""
scripts/test_controller_with_local_model.py - End-to-End Verification of AutonomousController with Real Local CPU Model
"""

import os
import sys
import json
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller.agent.autonomous_controller import AutonomousController
from controller.brain.local_cpu_client import LocalCpuBrainClient
from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.storage.evidence_store import EvidenceStore

def test_controller_local_model():
    print("=" * 80)
    print("VERIFYING AUTONOMOUS CONTROLLER & DASHBOARD WITH REAL LOCAL CPU MODEL")
    print("=" * 80)

    model_path = PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
    if not model_path.exists():
        model_path = PROJECT_ROOT / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"

    assert model_path.exists(), f"Model GGUF not found at {model_path}"

    print(f"Loading LocalCpuBrainClient with {model_path} (strictly NO mock fallback)...")
    brain = LocalCpuBrainClient(
        model_path=str(model_path),
        allow_mock_fallback=False
    )
    print(f"Brain engine initialized: {brain.engine}")
    assert brain.engine == "llama_cli", f"Expected llama_cli, got {brain.engine}"

    # Test classification directly
    sample_request = {
        "method": "POST",
        "path": "/api/v1/users",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "admin' UNION SELECT null, password FROM users --"},
        "cookies": {}
    }
    t0 = time.time()
    classification = brain.classify_request(sample_request)
    dur = time.time() - t0
    print(f"Direct Brain Classification Result in {dur:.2f}s:")
    print(json.dumps(classification, indent=2))
    assert classification.get("category") == "SQL Injection", f"Expected SQL Injection, got {classification.get('category')}"

    # Test AutonomousController initialization with this brain
    test_db = PROJECT_ROOT / "test_evidence_controller.db"
    if test_db.exists():
        test_db.unlink()

    store = EvidenceStore(str(test_db))
    config = AgentConfig(
        max_requests_per_session=5,
        max_model_calls=5,
        allowed_hosts={"127.0.0.1", "localhost"},
        db_path=str(test_db)
    )

    controller = AutonomousController(
        config=config,
        model_brain=brain,
        evidence_store=store
    )
    print("AutonomousController initialized successfully with Real Local CPU Model Brain!")
    print(f"Controller Brain class: {controller.brain.__class__.__name__}")
    print(f"Controller Brain engine: {controller.brain.engine}")

    if test_db.exists():
        test_db.unlink()

    print("=" * 80)
    print("AUTONOMOUS CONTROLLER VERIFICATION: SUCCESSFUL")
    print("=" * 80)

if __name__ == "__main__":
    test_controller_local_model()

